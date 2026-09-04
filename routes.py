import logging
from datetime import datetime

import pyotp
from flask import (
    render_template, redirect, url_for, flash, request, session, current_app,
)
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_

from app.auth import auth_bp
from app.extensions import db, limiter
from app.forms import RegistrationForm, LoginForm, OTPForm
from app.models import User

security_log = logging.getLogger("security")

# Keys used to track a login that has passed the password check but still
# needs a TOTP code. Nothing in `session` at this point counts as an
# authenticated Flask-Login session -- login_user() is only called once the
# OTP is verified.
PENDING_UID_KEY = "pending_2fa_user_id"
PENDING_REMEMBER_KEY = "pending_2fa_remember"


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        # SQLAlchemy's query API parameterizes these lookups -- user input
        # is never concatenated into a SQL string.
        existing = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()
        if existing:
            if existing.username == username:
                flash("That username is already taken.", "error")
            else:
                flash("An account with that email already exists.", "error")
            return render_template("register.html", form=form)

        user = User(username=username, email=email)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        security_log.info("New account registered: %s", username)
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()

        user = User.query.filter(
            or_(User.username == identifier, User.email == identifier.lower())
        ).first()

        if user and user.is_locked:
            remaining = max(user.lockout_seconds_remaining() // 60, 1)
            flash(
                f"This account is temporarily locked due to repeated failed "
                f"attempts. Try again in about {remaining} minute(s).",
                "error",
            )
            security_log.warning("Login blocked (locked account): %s", identifier)
            return render_template("login.html", form=form)

        if user and user.check_password(form.password.data):
            if user.is_2fa_enabled:
                # Password confirmed, but authentication isn't complete yet.
                session[PENDING_UID_KEY] = user.id
                session[PENDING_REMEMBER_KEY] = bool(form.remember_me.data)
                security_log.info("Password OK, awaiting OTP: %s", user.username)
                return redirect(url_for("auth.verify_2fa"))

            user.register_successful_login()
            login_user(user, remember=form.remember_me.data)
            session.permanent = True
            security_log.info("Login success: %s", user.username)
            flash(f"Welcome back, {user.username}.", "success")
            next_page = request.args.get("next")
            if next_page and not next_page.startswith("/"):
                next_page = None  # refuse open redirects to external hosts
            return redirect(next_page or url_for("main.dashboard"))

        # Invalid credentials. Record the failure against the account if it
        # exists, but show an identical, generic message either way so an
        # attacker can't use the error to enumerate valid usernames/emails.
        if user:
            user.register_failed_login(
                current_app.config["MAX_FAILED_LOGIN_ATTEMPTS"],
                current_app.config["LOCKOUT_DURATION"],
            )
            security_log.warning("Login failed (bad password): %s", identifier)
        else:
            security_log.warning("Login failed (unknown identifier): %s", identifier)

        flash("Invalid username/email or password.", "error")

    return render_template("login.html", form=form)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get(PENDING_UID_KEY)
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user or not user.is_2fa_enabled:
        session.pop(PENDING_UID_KEY, None)
        session.pop(PENDING_REMEMBER_KEY, None)
        return redirect(url_for("auth.login"))

    form = OTPForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.token.data, valid_window=1):
            remember = session.pop(PENDING_REMEMBER_KEY, False)
            session.pop(PENDING_UID_KEY, None)

            user.register_successful_login()
            login_user(user, remember=remember)
            session.permanent = True
            security_log.info("2FA success, login complete: %s", user.username)
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(url_for("main.dashboard"))

        user.register_failed_login(
            current_app.config["MAX_FAILED_LOGIN_ATTEMPTS"],
            current_app.config["LOCKOUT_DURATION"],
        )
        security_log.warning("2FA failed: %s", user.username)
        flash("That code didn't match. Try again.", "error")

    return render_template("verify_2fa.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    session.clear()
    security_log.info("Logout: %s", username)
    flash("You've been logged out.", "success")
    return redirect(url_for("main.home"))
