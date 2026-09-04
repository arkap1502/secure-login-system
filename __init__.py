import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template
from flask_wtf.csrf import CSRFError

from app.config import config_by_name
from app.extensions import db, login_manager, csrf, bcrypt, limiter


def create_app(config_name=None):
    config_name = config_name or os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_by_name[config_name])

    if config_name == "production" and app.config["SECRET_KEY"] == "dev-only-insecure-key-change-me":
        raise RuntimeError(
            "Refusing to start in production without a real SECRET_KEY. "
            "Set the SECRET_KEY environment variable."
        )

    os.makedirs(app.instance_path, exist_ok=True)

    _init_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_security_headers(app)
    _configure_logging(app)

    if config_name != "testing":
        with app.app_context():
            db.create_all()

    return app


def _init_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)


def _register_blueprints(app):
    from app.auth import auth_bp
    from app.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)


def _register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template("errors/429.html"), 429

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        # A bad/missing/expired CSRF token -- most commonly a stale form
        # left open in a browser tab. Send the user back to try again
        # rather than exposing the raw error.
        return render_template("errors/403.html", reason="csrf"), 400


def _register_security_headers(app):
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


def _configure_logging(app):
    log_dir = app.instance_path
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(log_dir, "security.log"), maxBytes=1_000_000, backupCount=3
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    security_log = logging.getLogger("security")
    security_log.setLevel(logging.INFO)
    if not security_log.handlers:
        security_log.addHandler(handler)
