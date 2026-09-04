# Vaultline — Secure Login System

A reference Flask application demonstrating secure user registration,
authentication, and session management: hashed passwords, rate-limited and
lockout-protected logins, CSRF-protected forms, ORM-only database access,
hardened session cookies, and optional TOTP-based two-factor authentication.

## Stack

- **Backend:** Python, Flask (application factory + blueprints)
- **Database:** SQLite (dev), via SQLAlchemy ORM
- **Auth/session:** Flask-Login
- **Forms/CSRF:** Flask-WTF (WTForms + CSRFProtect)
- **Password hashing:** bcrypt (Flask-Bcrypt)
- **Rate limiting:** Flask-Limiter
- **2FA:** PyOTP (TOTP) + `qrcode` for enrollment QR codes

## Project layout

```
secure-login-app/
├── run.py                     # entry point
├── requirements.txt
├── .env.example
├── app/
│   ├── __init__.py            # app factory, security headers, error handlers, logging
│   ├── config.py              # environment-driven configuration
│   ├── extensions.py          # db, login_manager, csrf, bcrypt, limiter
│   ├── models.py              # User model (hashing, lockout, TOTP fields)
│   ├── forms.py                # WTForms definitions + validators
│   ├── utils.py                # password policy logic (shared by form + UI)
│   ├── auth/                  # register / login / 2FA verification / logout
│   ├── main/                  # home / dashboard / profile / 2FA setup
│   ├── templates/
│   └── static/
│       ├── css/style.css
│       └── js/
└── instance/                  # SQLite db + security.log (git-ignored, created at runtime)
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # paste into .env as SECRET_KEY

python run.py
```

Visit `http://127.0.0.1:5000`. The SQLite database and tables are created
automatically on first run, inside `instance/`.

## How each requirement is implemented

**Registration & validation** — `app/forms.py` validates username format/length,
email format, and password strength server-side with WTForms validators
before anything reaches the database. `app/auth/routes.py` checks for an
existing username/email via a single parameterized SQLAlchemy query before
creating the account.

**Password storage** — `User.set_password()` / `check_password()` in
`app/models.py` hash and verify with bcrypt (via Flask-Bcrypt). The
plaintext password is never written to the database or logged.

**Login & brute-force protection** — `app/auth/routes.py` combines:
- Flask-Limiter on the `/login` route (10 requests/minute per IP), and
- a per-account lockout (`failed_login_attempts` / `locked_until` on `User`,
  configurable via `MAX_FAILED_LOGIN_ATTEMPTS` / `LOCKOUT_DURATION`).

Invalid username and invalid password both return the same generic error
message, so the login form can't be used to enumerate valid accounts.

**Input validation & SQL injection protection** — every database read/write
goes through the SQLAlchemy ORM's query API (`User.query.filter(...)`,
`db.session.get(...)`, etc.), which parameterizes all values. No raw SQL
strings are built from user input anywhere in the app.

**Session management** — Flask-Login manages the session; cookies are
`HttpOnly` and `SameSite=Lax`, sessions idle out after 30 minutes
(`PERMANENT_SESSION_LIFETIME`), and `session_protection = "strong"` ties the
session to the client. `@login_required` guards `/dashboard`, `/profile`,
and the 2FA management routes, redirecting unauthenticated visitors to
`/login?next=...`. `/logout` calls `logout_user()` and clears the session.

**CSRF / secure cookies / headers** — `CSRFProtect` is enabled globally, so
every POST form requires a valid per-session token (see `form.hidden_tag()`
in the templates). `app/__init__.py` also sets `X-Content-Type-Options`,
`X-Frame-Options`, a restrictive `Content-Security-Policy`, and
`Strict-Transport-Security` once HTTPS is enabled.

**HTTPS-ready** — cookies are only marked `Secure` when `FORCE_HTTPS=true`
(see `.env.example`), since a `Secure` cookie sent over plain HTTP is simply
dropped by the browser. Set `FORCE_HTTPS=true` once the app is actually
served behind TLS (e.g. behind a reverse proxy terminating HTTPS).

**Two-factor authentication (optional)** — `app/main/routes.py` generates a
TOTP secret and a QR enrollment code (`pyotp` + `qrcode`) that is only
persisted to the user's account once they prove they can generate a valid
code with it. At login, a correct password with 2FA enabled sets a
*pending* (not-yet-authenticated) session marker and redirects to
`/verify-2fa`; `login_user()` is only called after a valid OTP is checked.

## Notes on running this in production

This is a learning/demo-grade reference build. Before deploying for real:

- Put it behind a real WSGI server (gunicorn/uWSGI) and a reverse proxy
  terminating TLS; set `FORCE_HTTPS=true` and `FLASK_ENV=production`.
- Point `RATELIMIT_STORAGE_URI` at Redis (or similar) if you run more than
  one process/worker, since the default in-memory limiter store doesn't
  share state across processes.
- Swap SQLite for Postgres/MySQL for concurrent write load, and manage
  schema changes with Flask-Migrate instead of `db.create_all()`.
- Consider adding email verification and a password-reset flow (deliberately
  out of scope here to keep the reference focused).
