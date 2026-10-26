"""Flask application factory for CyberTrace."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session
from neo4j.exceptions import Neo4jError
from werkzeug.middleware.proxy_fix import ProxyFix

from .api import api
from .auth import auth, configured, protect_api
from .collaboration import collaboration
from .config import Settings
from .db import Neo4jDatabase
from .store import AppStore


def create_app(
    settings: Settings | None = None,
    *,
    database_factory: type[Neo4jDatabase] = Neo4jDatabase,
) -> Flask:
    frontend = Path(__file__).resolve().parent.parent / "frontend"
    app = Flask(__name__, static_folder=str(frontend), static_url_path="/static")
    resolved_settings = settings or Settings.from_env()
    if resolved_settings.require_https and resolved_settings.flask_debug:
        raise ValueError("Debug mode cannot be used with HTTPS enforcement")
    if resolved_settings.require_https and len(resolved_settings.secret_key) < 32:
        raise ValueError("HTTPS deployments require a secret key of at least 32 characters")
    if resolved_settings.trusted_proxy_count:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=resolved_settings.trusted_proxy_count)
    app.secret_key = resolved_settings.secret_key
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=resolved_settings.require_https,
        PERMANENT_SESSION_LIFETIME=3600,
        TRUSTED_HOSTS=list(resolved_settings.trusted_hosts),
        MAX_CONTENT_LENGTH=250_000,
    )
    app.extensions["settings"] = resolved_settings
    with app.app_context():
        configured()
    store = AppStore(resolved_settings.app_database_path)
    store.seed_admin(resolved_settings.admin_username, resolved_settings.admin_password_hash)
    app.extensions["app_store"] = store
    database = database_factory(resolved_settings)
    app.extensions["neo4j"] = database
    app.register_blueprint(api)
    app.register_blueprint(auth)
    app.register_blueprint(collaboration)
    app.before_request(protect_api)

    @app.before_request
    def enforce_transport():
        if resolved_settings.require_https and not request.is_secure:
            return jsonify(error="HTTPS is required"), 403
        return None

    @app.after_request
    def security_headers(response):
        if request.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            store.record_audit(session.get("user", "anonymous"), request.method, request.path, response.status_code)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        if resolved_settings.require_https:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.get("/api/health")
    def health():
        try:
            database.verify_connectivity()
        except Neo4jError as exc:
            return jsonify(
                status="unhealthy", database="unavailable", error=exc.__class__.__name__
            ), 503
        return jsonify(status="healthy", database="connected")

    @app.get("/api")
    def api_root():
        return jsonify(name="CyberTrace API", phase="foundation", version="0.1.0")

    @app.get("/")
    def frontend_root():
        return send_from_directory(frontend, "index.html")

    @app.errorhandler(Neo4jError)
    def database_error(error: Neo4jError):
        return jsonify(
            error="Database operation failed", code=error.__class__.__name__
        ), 503

    return app


def main() -> None:
    settings = Settings.from_env()
    app = create_app(settings)
    try:
        app.run(
            host=settings.flask_host,
            port=settings.flask_port,
            debug=settings.flask_debug,
        )
    finally:
        app.extensions["neo4j"].close()


if __name__ == "__main__":
    main()
