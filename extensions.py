"""
Flask extension instances, created here (unbound) and initialized against
the app in app/__init__.py. Keeping them in one module avoids circular
imports between models, blueprints, and the app factory.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
bcrypt = Bcrypt()
limiter = Limiter(key_func=get_remote_address)

login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to view that page."
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"
