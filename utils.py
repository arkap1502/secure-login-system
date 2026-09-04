"""
Small, dependency-free helpers used by the forms and routes.
"""
import re

# A short blocklist of extremely common passwords. This is not meant to be
# exhaustive -- it's a cheap extra check on top of the structural rules
# below (length, character classes) that catches the most obvious choices.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwertyuiop", "letmein123", "welcome123", "iloveyou", "admin1234",
    "changeme", "123123123", "qwerty123", "football1", "monkey123",
}


def password_policy_errors(password, min_length=10, username=None, email=None):
    """
    Return a list of human-readable reasons a password fails the policy.
    An empty list means the password is acceptable. Centralizing this here
    means the server-side WTForms validator and any other server-side check
    apply exactly the same rules.
    """
    errors = []

    if len(password) < min_length:
        errors.append(f"Use at least {min_length} characters.")
    if not re.search(r"[a-z]", password):
        errors.append("Include at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Include at least one uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Include at least one number.")
    if not re.search(r"[^\w\s]", password):
        errors.append("Include at least one special character.")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("This password is too common. Choose something less predictable.")
    if username and username.lower() in password.lower():
        errors.append("Password must not contain your username.")
    if email:
        local_part = email.split("@")[0].lower()
        if local_part and local_part in password.lower():
            errors.append("Password must not contain part of your email address.")

    return errors


def password_strength_score(password):
    """
    A rough 0-4 strength score, used only to drive the UI meter. The
    authoritative check is password_policy_errors() above.
    """
    score = 0
    if len(password) >= 10:
        score += 1
    if len(password) >= 14:
        score += 1
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[^\w\s]", password):
        score += 1
    return min(score, 4)
