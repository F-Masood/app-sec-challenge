# Appsec Challenge - Readme

##### Agenda/Goal --- Enhance the existing login form to meet modern security standards.

#### Process
* Analyse the problem
* Identify threats
* Implement controls

#### Tech Stack
* HTML and Python (Flask)
* HTML hosts pages like Login, MFA, Forgot Passwords etc
* Core logic / route is defined in "app.py"

##### Packages used
* Flask	--- Core app
* Flask-WTF	--- CSRF + form validation
* Flask-SQLAlchemy --- Safe DB access
* Flask-Limiter	--- Rate limiting
* Flask-Talisman --- Security headers
* itsdangerous --- Signed reset tokens
* pyotp	--- MFA
* msal	--- Azure SSO
* passlib[argon2] --- Strong password hashing
* email-validator --- Proper email validation

#### To run
* Clone this repo
* Run commands:
    * sudo apt install -y python3-venv
    * python3 -m venv .venv
    * source .venv/bin/activate
    * pip install Flask Flask-WTF Flask-SQLAlchemy Flask-Limiter Flask-Talisman email-validator itsdangerous pyotp msal "passlib[argon2]" 
* And then run:
    * python3 app.py
    * Open web browser and navigate to following URL: 
        http://127.0.0.1:5000
* Tested on:
    * OS: Kali Linux 2023.4
    * Python Version: Python 3.13.11

#### Safeguards 
##### Method (A) - Username / Password
* Login / Authentication (Client Side)
    * Check if the email is valid and ends with "*@xero.com".
* Password Algorithm:
    Strong algorithm (Argon2 password hashing), which makes HASHes hard (too much time) to crack
    Not storing creds in plaintext
* For Normal users:
    * Have strong password policy (as per OWASP/NZISM/NIST)
* For Admin users:
    * Have MFA enabled too 
    * Admin users can also create new users
* Generic error messages on:
    * Username/ password fails
    * User's password / forgotten password feature
* Session security:
    * Session cleared on login (prevents session fixation) 
    * SESSION_COOKIE_HTTPONLY = True 
    * SESSION_COOKIE_SAMESITE = "Lax" 
    * Manual cookie deletion on logout Unique session_id generated
    * SESSION_COOKIE_SECURE = False (dev mode)
* Header security:
    * CSP (default-src 'self')
    * frame-ancestors 'none'
    * HSTS (1 year + preload)
    * Base URI restriction
* CSRF
    * CSRFProtect(app) via Flask-WTF
* Rate-limiting
    * 10 requests per second per IP
* Account Lockout
    * Admin accounts get locked on repeated failed attempts
* Logging
    * Log all activity with timestamp
##### Method (B) - SSO (Google, Microsoft or Okta etc.)
* Pros:
    * No need to have separate logic / DBs for Authentication part
* Cons:
    * The SSO policies will be effective, so granular control e.g. Password policy, Session timeout etc. can’t be controlled

#####  Other safeguards to implement in future
* Host header injection
* IP-allow listing:
    * Behind VPN or Azure CAP to access this portal to reduce attack surface
* Local WAF
* Captcha 
* Package scanning / Pipeline scanning to find CVEs
* Use an API or custom-dict to block most common keywords for PWD e.g.:
    * Xero
    * Newzealand
    * Kiwi 
    * etc. etc. etc. 

#####  Other functionality
* Beautfiy web



#### References / Sources used
* Google, ChatGPT, Github and Flask documentation
* For ChatGPT part:
    Creds and other sensitive information was not thrown to AI