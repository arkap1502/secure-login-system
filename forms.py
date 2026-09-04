"""
All forms in the app use Flask-WTF, which:
  - issues and validates a CSRF token on every POST automatically, and
  - runs these validators server-side before any data touches the database,

so no user input reaches the ORM (and therefore the database) unvalidated.
"""
import re

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Regexp, ValidationError,
)

from app.utils import password_policy_errors

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]+$")


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=30, message="Username must be 3-30 characters."),
            Regexp(USERNAME_RE, message="Letters, numbers, and underscores only."),
        ],
    )
    email = StringField(
        "Email address",
        validators=[DataRequired(), Email(message="Enter a valid email address."), Length(max=255)],
    )
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords do not match.")],
    )
    submit = SubmitField("Create account")

    def validate_password(self, field):
        errors = password_policy_errors(
            field.data,
            username=self.username.data,
            email=self.email.data,
        )
        if errors:
            raise ValidationError(" ".join(errors))


class LoginForm(FlaskForm):
    identifier = StringField("Username or email", validators=[DataRequired(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Keep me signed in")
    submit = SubmitField("Log in")


class OTPForm(FlaskForm):
    token = StringField(
        "6-digit code",
        validators=[
            DataRequired(),
            Regexp(r"^\d{6}$", message="Enter the 6-digit code from your authenticator app."),
        ],
    )
    submit = SubmitField("Verify")


class Enable2FAForm(FlaskForm):
    token = StringField(
        "6-digit code",
        validators=[
            DataRequired(),
            Regexp(r"^\d{6}$", message="Enter the 6-digit code from your authenticator app."),
        ],
    )
    submit = SubmitField("Enable two-factor authentication")


class Disable2FAForm(FlaskForm):
    password = PasswordField("Confirm your password", validators=[DataRequired()])
    submit = SubmitField("Disable two-factor authentication")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired()])
    confirm_new_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords do not match.")],
    )
    submit = SubmitField("Update password")

    def validate_new_password(self, field):
        errors = password_policy_errors(field.data)
        if errors:
            raise ValidationError(" ".join(errors))
