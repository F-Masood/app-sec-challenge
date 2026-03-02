# app.py
#
# Sample Flask auth app (plain + readable) with:
# - Local login (email+password) restricted to *@xero.com
# - Optional MFA using TOTP (Google Authenticator) via pyotp
# - Forgot password / reset with generic anti-enumeration message
# - Request logging (timestamp, IP, method, path, status, duration, request id)
# - Rate limiting: 10 requests/second per IP (Flask-Limiter)
# - Admin lockout after 10 failed attempts (example policy)
# - Secure headers via Flask-Talisman (CSP, frame-ancestors, etc.)
# - CSRF protection via Flask-WTF
# - /dev/create-user protected with HTTP Basic using a local file dev_basic_auth.txt
#   (NO env creds, NO passlib htpasswd, avoids bcrypt/passlib compatibility issues)
# - Microsoft Entra ID (Azure AD) SSO via MSAL
#
# Files needed:
# - app.py
# - templates/login.html
# - templates/mfa.html
# - templates/forgot_password.html
# - templates/reset_password.html
# - templates/message.html
# - templates/dev_create_user.html

#
# Run:
#   python app.py

import os
import re
import time
import uuid
import base64
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, render_template, redirect, url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import CSRFError
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, Length

from passlib.hash import argon2

from werkzeug.security import check_password_hash

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import pyotp
import msal

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman


# ----------------------------
# Config
# ----------------------------

XERO_EMAIL_REGEX = re.compile(r"^[^@]+@xero\.com$", re.IGNORECASE)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth_demo.db")
DEV_BASIC_PATH = os.path.join(BASE_DIR, "dev_basic_auth.txt")

app = Flask(__name__)

# In production: set these via environment / secret manager.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-change-me-please")
app.config["RESET_TOKEN_SECRET"] = os.environ.get("RESET_TOKEN_SECRET", "reset-dev-change-me")

# Absolute SQLite path (no surprises)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Cookies: set SESSION_COOKIE_SECURE=True when serving over HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # set True in production behind HTTPS

# MSAL / Entra ID config (set env vars if you want SSO to work)
app.config["MSAL_CLIENT_ID"] = os.environ.get("MSAL_CLIENT_ID", "")
app.config["MSAL_CLIENT_SECRET"] = os.environ.get("MSAL_CLIENT_SECRET", "")
app.config["MSAL_TENANT_ID"] = os.environ.get("MSAL_TENANT_ID", "")
app.config["MSAL_REDIRECT_PATH"] = "/auth/entra/callback"
app.config["MSAL_AUTHORITY"] = (
    f"https://login.microsoftonline.com/{app.config['MSAL_TENANT_ID']}"
    if app.config["MSAL_TENANT_ID"] else ""
)
app.config["MSAL_SCOPES"] = ["openid", "profile", "email"]

db = SQLAlchemy(app)
csrf = CSRFProtect(app)


# ----------------------------
# Logging (requests)
# ----------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s %(message)s",
)
logger = logging.getLogger("auth_app")


@app.before_request
def start_timer_and_request_id():
    request.start_time = time.time()
    request.request_id = str(uuid.uuid4())


@app.after_request
def log_request(response):
    duration_ms = int((time.time() - getattr(request, "start_time", time.time())) * 1000)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    logger.info(
        "rid=%s ip=%s method=%s path=%s status=%s duration_ms=%s",
        getattr(request, "request_id", "-"),
        ip,
        request.method,
        request.path,
        response.status_code,
        duration_ms,
    )
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template("message.html", title="Error", message="Request failed security validation."), 400


# ----------------------------
# Security headers (Talisman)
# ----------------------------

csp = {
    "default-src": "'self'",
    "style-src": "'self'",
    "script-src": "'self'",
    "img-src": "'self' data:",
    "base-uri": "'self'",
    "frame-ancestors": "'none'",
}

# For local dev over HTTP keep force_https=False.
# For production behind HTTPS, set force_https=True and SESSION_COOKIE_SECURE=True.
Talisman(
    app,
    content_security_policy=csp,
    force_https=False,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,
)


# ----------------------------
# Rate limiting
# ----------------------------

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.environ.get("LIMITER_STORAGE_URI", "memory://"),
    default_limits=[],
)


@app.before_request
@limiter.limit("10 per second")
def global_rate_limit():
    pass


# ----------------------------
# DB model
# ----------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.Text, nullable=True)

    is_admin = db.Column(db.Boolean, default=False)

    # TOTP secret (if MFA enabled)
    totp_secret = db.Column(db.String(64), nullable=True)

    # Lockout tracking
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until_utc = db.Column(db.DateTime, nullable=True)

    created_at_utc = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


def init_db():
    with app.app_context():
        db.create_all()


# ----------------------------
# Forms
# ----------------------------

class LoginForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])


class MFAForm(FlaskForm):
    totp = StringField("MFA code", validators=[DataRequired(), Length(min=6, max=10)])


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), Email(), Length(max=255)])


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(min=12, max=128)])
    totp = StringField("MFA code (if enabled)", validators=[Length(min=0, max=10)])


class DevCreateUserForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=12, max=128)])
    is_admin = BooleanField("Admin user?")
    enable_mfa = BooleanField("Enable MFA (TOTP)?")


# ----------------------------
# Helpers
# ----------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def is_valid_xero_email(email: str) -> bool:
    return bool(XERO_EMAIL_REGEX.match(email or ""))


def generic_login_error():
    flash("Invalid credentials.", "error")


def is_locked(user: User) -> bool:
    return bool(user.locked_until_utc and now_utc() < user.locked_until_utc)


def record_failed_login(user: User):
    user.failed_attempts = (user.failed_attempts or 0) + 1

    # Lockout policy (example): only lock admin accounts
    if user.is_admin and user.failed_attempts >= 10:
        user.locked_until_utc = now_utc() + timedelta(minutes=30)

    db.session.commit()


def reset_failed_logins(user: User):
    user.failed_attempts = 0
    user.locked_until_utc = None
    db.session.commit()


def get_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config["RESET_TOKEN_SECRET"])


def make_reset_token(email: str) -> str:
    return get_serializer().dumps({"email": email})


def verify_reset_token(token: str, max_age_seconds: int = 3600) -> str | None:
    try:
        data = get_serializer().loads(token, max_age=max_age_seconds)
        return data.get("email")
    except (SignatureExpired, BadSignature):
        return None


def send_reset_email_stub(email: str, reset_url: str):
    # Stub only. In real systems: send email; don't log reset_url.
    logger.info("password_reset_requested email=%s rid=%s", email, request.request_id)
    logger.info("DEV reset_url=%s", reset_url)


def login_user(email: str):
    # Rotate session on login (prevents session fixation)
    session.clear()
    session["user_email"] = email
    session["session_id"] = str(uuid.uuid4())


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_email"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


# ----------------------------
# HTTP Basic auth for /dev/create-user using dev_basic_auth.txt
# ----------------------------

def _basic_auth_challenge():
    r = app.make_response("Authentication required")
    r.status_code = 401
    r.headers["WWW-Authenticate"] = 'Basic realm="Dev Area"'
    return r


def _load_dev_basic_credentials():
    """
    File format:  username:pbkdf2_hash
    Example:
      devadmin:pbkdf2:sha256:600000$...$...
    """
    if not os.path.exists(DEV_BASIC_PATH):
        abort(500, "Missing dev_basic_auth.txt (create it using the helper snippet in app.py header).")

    line = open(DEV_BASIC_PATH, "r", encoding="utf-8").read().strip()
    if ":" not in line:
        abort(500, "Invalid dev_basic_auth.txt format. Expected: username:hash")

    username, pw_hash = line.split(":", 1)
    if not username or not pw_hash:
        abort(500, "Invalid dev_basic_auth.txt contents.")
    return username, pw_hash


def require_basic_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        expected_user, expected_hash = _load_dev_basic_credentials()

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return _basic_auth_challenge()

        try:
            raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            username, password = raw.split(":", 1)
        except Exception:
            return _basic_auth_challenge()

        ok = (username == expected_user) and check_password_hash(expected_hash, password)
        if not ok:
            return _basic_auth_challenge()

        return fn(*args, **kwargs)
    return wrapper


# ----------------------------
# Entra SSO (MSAL)
# ----------------------------

def build_msal_app():
    if not app.config["MSAL_CLIENT_ID"] or not app.config["MSAL_AUTHORITY"]:
        return None
    return msal.ConfidentialClientApplication(
        client_id=app.config["MSAL_CLIENT_ID"],
        client_credential=app.config["MSAL_CLIENT_SECRET"],
        authority=app.config["MSAL_AUTHORITY"],
    )


# ----------------------------
# Routes
# ----------------------------

@app.get("/")
@require_login
def home():
    return render_template("message.html", title="Signed in", message=f"Signed in as {session['user_email']}")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data.strip().lower()
        password = form.password.data

        # Server-side allowlist: only *@xero.com
        if not is_valid_xero_email(email):
            generic_login_error()
            return render_template("login.html", form=form)

        user = User.query.filter_by(email=email).first()
        if not user:
            generic_login_error()
            return render_template("login.html", form=form)

        # Locked admins: still generic response
        if is_locked(user):
            generic_login_error()
            return render_template("login.html", form=form)

        # Verify password (argon2)
        if not user.password_hash or not argon2.verify(password, user.password_hash):
            record_failed_login(user)
            generic_login_error()
            return render_template("login.html", form=form)

        reset_failed_logins(user)

        # MFA step (if enabled)
        if user.totp_secret:
            session.clear()
            session["preauth_email"] = user.email
            return redirect(url_for("mfa"))

        login_user(user.email)
        logger.info("login_success email=%s method=password rid=%s", user.email, request.request_id)
        return redirect(url_for("home"))

    return render_template("login.html", form=form)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    preauth_email = session.get("preauth_email")
    if not preauth_email:
        return redirect(url_for("login"))

    user = User.query.filter_by(email=preauth_email).first()
    if not user or not user.totp_secret:
        return redirect(url_for("login"))

    form = MFAForm()
    if request.method == "POST" and form.validate_on_submit():
        code = form.totp.data.strip()

        if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
            flash("Invalid verification code.", "error")
            logger.info("mfa_failed email=%s rid=%s", user.email, request.request_id)
            return render_template("mfa.html", form=form)

        login_user(user.email)
        logger.info("login_success email=%s method=password+mfa rid=%s", user.email, request.request_id)
        return redirect(url_for("home"))

    return render_template("mfa.html", form=form)


@app.get("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    resp = redirect(url_for("login"))
    resp.delete_cookie("session")
    return resp


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()

    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data.strip().lower()

        # Always show generic message (anti-enumeration)
        if is_valid_xero_email(email):
            user = User.query.filter_by(email=email).first()
            if user:
                token = make_reset_token(email)
                reset_url = url_for("reset_password", token=token, _external=True)
                send_reset_email_stub(email, reset_url)

        return render_template(
            "message.html",
            title="Reset requested",
            message="If your email existed in our system, you will receive a reset email shortly.",
        )

    return render_template("forgot_password.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    email = verify_reset_token(token, max_age_seconds=3600)
    if not email:
        return render_template("message.html", title="Invalid link", message="This reset link is invalid or expired.")

    user = User.query.filter_by(email=email).first()
    if not user:
        return render_template("message.html", title="Invalid link", message="This reset link is invalid or expired.")

    form = ResetPasswordForm()
    if request.method == "POST" and form.validate_on_submit():
        new_password = form.password.data

        # If MFA enabled, require TOTP for reset (optional but sensible)
        if user.totp_secret:
            code = (form.totp.data or "").strip()
            if not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
                flash("Invalid verification code.", "error")
                return render_template("reset_password.html", form=form)

        user.password_hash = argon2.hash(new_password)
        reset_failed_logins(user)
        db.session.commit()

        # Force re-login after reset
        session.clear()

        logger.info("password_reset_success email=%s rid=%s", user.email, request.request_id)
        return render_template("message.html", title="Password updated", message="Your password has been updated. Please sign in.")

    return render_template("reset_password.html", form=form)


@app.route("/dev/create-user", methods=["GET", "POST"])
@require_basic_auth
def dev_create_user():
    init_db()
    form = DevCreateUserForm()

    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data.strip().lower()

        # Keep consistent: only allow @xero.com users
        if not is_valid_xero_email(email):
            flash("Only @xero.com emails are allowed.", "error")
            return render_template("dev_create_user.html", form=form)

        if User.query.filter_by(email=email).first():
            flash("User already exists.", "error")
            return render_template("dev_create_user.html", form=form)

        totp_secret = pyotp.random_base32() if form.enable_mfa.data else None

        user = User(
            email=email,
            password_hash=argon2.hash(form.password.data),
            is_admin=bool(form.is_admin.data),
            totp_secret=totp_secret,
        )
        db.session.add(user)
        db.session.commit()

        msg = f"Created user: {email}. Admin={user.is_admin}. MFA={'enabled' if totp_secret else 'disabled'}."
        if totp_secret:
            msg += f" TOTP secret (DEV ONLY): {totp_secret}"

        return render_template("message.html", title="User created", message=msg)

    return render_template("dev_create_user.html", form=form)


@app.get("/auth/entra/login")
def entra_login():
    msal_app = build_msal_app()
    if not msal_app:
        return render_template("message.html", title="SSO not configured", message="Set MSAL_CLIENT_ID/SECRET/TENANT_ID env vars.")

    state = str(uuid.uuid4())
    session["msal_state"] = state

    auth_url = msal_app.get_authorization_request_url(
        scopes=app.config["MSAL_SCOPES"],
        state=state,
        redirect_uri=url_for("entra_callback", _external=True),
        prompt="select_account",
    )
    return redirect(auth_url)


@app.get("/auth/entra/callback")
def entra_callback():
    if request.args.get("state") != session.get("msal_state"):
        abort(400, "Invalid state.")

    msal_app = build_msal_app()
    if not msal_app:
        abort(500)

    code = request.args.get("code")
    if not code:
        abort(400, "Missing code.")

    result = msal_app.acquire_token_by_authorization_code(
        code=code,
        scopes=app.config["MSAL_SCOPES"],
        redirect_uri=url_for("entra_callback", _external=True),
    )

    if "error" in result:
        logger.info("entra_login_failed error=%s rid=%s", result.get("error"), request.request_id)
        return render_template("message.html", title="SSO failed", message="Single sign-on failed. Please try again.")

    claims = result.get("id_token_claims", {}) or {}
    email = (claims.get("preferred_username") or claims.get("email") or "").strip().lower()

    # Apply same restriction for SSO
    if not is_valid_xero_email(email):
        logger.info("entra_login_denied email=%s rid=%s", email, request.request_id)
        return render_template("message.html", title="Access denied", message="Access denied.")

    init_db()
    user = User.query.filter_by(email=email).first()
    if not user:
        # JIT provisioning: create record without local password
        user = User(email=email, password_hash=None, is_admin=False, totp_secret=None)
        db.session.add(user)
        db.session.commit()

    login_user(email)
    logger.info("login_success email=%s method=entra_sso rid=%s", email, request.request_id)
    return redirect(url_for("home"))


# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
