"""Session authentication and role checks for the CyberTrace API."""

from __future__ import annotations

import secrets

from flask import Blueprint, current_app, jsonify, request, session
auth = Blueprint("auth", __name__, url_prefix="/api/auth")


def configured() -> None:
    settings = current_app.extensions["settings"]
    if not settings.secret_key or not settings.admin_password_hash:
        raise RuntimeError(
            "Set CYBERTRACE_SECRET_KEY and CYBERTRACE_ADMIN_PASSWORD_HASH in .env"
        )


def logged_in() -> bool:
    username = session.get("user")
    if not username:
        return False
    user = current_app.extensions["app_store"].user(username)
    return bool(user and not user["disabled"])


def current_role() -> str:
    if not logged_in():
        return ""
    return current_app.extensions["app_store"].user(session["user"])["role"]


def protect_api():
    if not request.path.startswith("/api/") and request.path != "/api":
        return None
    if request.path in {"/api/health", "/api/auth/login", "/api/auth/session"}:
        return None
    if not logged_in():
        return jsonify(error="Sign in is required"), 401
    role = current_role()
    if request.path.startswith("/api/admin/") and role != "admin":
        return jsonify(error="Administrator access is required"), 403
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.path.startswith(("/api/entities", "/api/relationships", "/api/reports")) and role == "viewer":
            return jsonify(error="Analyst access is required"), 403
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("csrf_token", "")
        received = request.headers.get("X-CSRF-Token", "")
        if not expected or not secrets.compare_digest(expected, received):
            return jsonify(error="A valid CSRF token is required"), 403
    return None


@auth.post("/login")
def login():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="A JSON object body is required"), 400
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Username and password are required"), 400
    store = current_app.extensions["app_store"]
    address = request.remote_addr or "unknown"
    if store.blocked_login(username, address):
        return jsonify(error="Too many sign-in attempts; try again in 15 minutes"), 429
    user = store.authenticate(username, password)
    store.record_login(username, address, success=bool(user))
    if not user:
        return jsonify(error="Invalid username or password"), 401
    session.clear()
    session.permanent = True
    session["user"] = username
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(username=username, role=user["role"], csrf_token=session["csrf_token"])


@auth.get("/session")
def session_status():
    if not logged_in():
        return jsonify(authenticated=False)
    return jsonify(
        authenticated=True,
        username=session["user"],
        role=current_role(),
        csrf_token=session["csrf_token"],
    )


@auth.post("/logout")
def logout():
    session.clear()
    return jsonify(authenticated=False)
