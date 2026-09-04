import base64
import io
import logging

import pyotp
import qrcode
from flask import render_template, redirect, url_for, flash, session, current_app
from flask_login import login_required, current_user

from app.main import main_bp
from app.extensions import db
from app.forms import Enable2FAForm, Disable2FAForm, ChangePasswordForm

security_log = logging.getLogger("security")

PENDING_OTP_SECRET_KEY = "pending_otp_secret"


@main_bp.route("/")
def home():
    return render_template("home.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@main_bp.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@main_bp.route("/profile/security/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Current password is incorrect.", "error")
            return render_template("change_password.html", form=form)

        current_user.set_password(form.new_password.data)
        db.session.commit()
        security_log.info("Password changed: %s", current_user.username)
        flash("Password updated.", "success")
        return redirect(url_for("main.profile"))

    return render_template("change_password.html", form=form)


@main_bp.route("/profile/security/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if current_user.is_2fa_enabled:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("main.profile"))

    # Generate (or reuse, within this session) a secret that is NOT yet
    # saved to the user's account. It only becomes permanent once the user
    # proves they can generate a valid code with it.
    secret = session.get(PENDING_OTP_SECRET_KEY)
    if not secret:
        secret = pyotp.random_base32()
        session[PENDING_OTP_SECRET_KEY] = secret

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name=current_app.config["TOTP_ISSUER"]
    )
    qr_data_uri = _qr_data_uri(provisioning_uri)

    form = Enable2FAForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(secret)
        if totp.verify(form.token.data, valid_window=1):
            current_user.otp_secret = secret
            current_user.is_2fa_enabled = True
            db.session.commit()
            session.pop(PENDING_OTP_SECRET_KEY, None)
            security_log.info("2FA enabled: %s", current_user.username)
            flash("Two-factor authentication is now enabled.", "success")
            return redirect(url_for("main.profile"))

        flash("That code didn't match. Scan the QR code again and retry.", "error")

    return render_template(
        "setup_2fa.html", form=form, qr_data_uri=qr_data_uri, secret=secret
    )


@main_bp.route("/profile/security/2fa/disable", methods=["GET", "POST"])
@login_required
def disable_2fa():
    if not current_user.is_2fa_enabled:
        return redirect(url_for("main.profile"))

    form = Disable2FAForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.password.data):
            flash("Incorrect password.", "error")
            return render_template("disable_2fa.html", form=form)

        current_user.is_2fa_enabled = False
        current_user.otp_secret = None
        db.session.commit()
        security_log.info("2FA disabled: %s", current_user.username)
        flash("Two-factor authentication has been disabled.", "success")
        return redirect(url_for("main.profile"))

    return render_template("disable_2fa.html", form=form)


def _qr_data_uri(data):
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
