"""
Database models.

All queries against these models go through SQLAlchemy's ORM (see
app/auth/routes.py and app/main/routes.py), which parameterizes every
query automatically -- user input is never interpolated into SQL strings,
which is what prevents SQL injection here.
"""
from datetime import datetime, timedelta

from flask_login import UserMixin

from app.extensions import db, bcrypt, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # --- Brute-force / lockout tracking ---
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    # --- Two-factor authentication (TOTP) ---
    otp_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # ---- Password handling ----
    def set_password(self, plaintext_password):
        self.password_hash = bcrypt.generate_password_hash(plaintext_password).decode("utf-8")

    def check_password(self, plaintext_password):
        return bcrypt.check_password_hash(self.password_hash, plaintext_password)

    # ---- Lockout handling ----
    @property
    def is_locked(self):
        return bool(self.locked_until and self.locked_until > datetime.utcnow())

    def register_failed_login(self, max_attempts, lockout_duration):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.utcnow() + lockout_duration
        db.session.commit()

    def register_successful_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_at = datetime.utcnow()
        db.session.commit()

    def lockout_seconds_remaining(self):
        if not self.is_locked:
            return 0
        return int((self.locked_until - datetime.utcnow()).total_seconds())

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    # Flask-Login passes the id stored in the session; SQLAlchemy's
    # Session.get() is a simple, safe, parameterized primary-key lookup.
    return db.session.get(User, int(user_id))
