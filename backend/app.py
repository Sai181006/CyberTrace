"""Flask application factory for CyberTrace."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, send_from_directory
from neo4j.exceptions import Neo4jError

from .api import api
from .auth import auth, configured, protect_api
from .config import Settings
from .db import Neo4jDatabase


def create_app(
    settings: Settings | None = None,
    *,
    database_factory: type[Neo4jDatabase] = Neo4jDatabase,
) -> Flask:
    frontend = Path(__file__).resolve().parent.parent / "frontend"
    app = Flask(__name__, static_folder=str(frontend), static_url_path="/static")
    resolved_settings = settings or Settings.from_env()
    app.secret_key = resolved_settings.secret_key
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=3600,
    )
    app.extensions["settings"] = resolved_settings
    with app.app_context():
        configured()
    database = database_factory(resolved_settings)
    app.extensions["neo4j"] = database
    app.register_blueprint(api)
    app.register_blueprint(auth)
    app.before_request(protect_api)

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
