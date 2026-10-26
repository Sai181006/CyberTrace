"""Shared reports, user administration, source history, and analyst evaluation."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .auth import current_role
from .evaluation import grade, tasks_for_mode
from .entities import entity_spec
from .data.loader import ALLOWED_RELATIONSHIPS

collaboration = Blueprint("collaboration", __name__, url_prefix="/api")


def _store():
    return current_app.extensions["app_store"]


def _body() -> dict:
    value = request.get_json(silent=True)
    if not isinstance(value, dict):
        raise ValueError("A JSON object body is required")
    return value


@collaboration.errorhandler(ValueError)
def bad_request(error: ValueError):
    return jsonify(error=str(error)), 400


@collaboration.errorhandler(LookupError)
def not_found(error: LookupError):
    return jsonify(error=str(error)), 404


@collaboration.errorhandler(PermissionError)
def forbidden(error: PermissionError):
    return jsonify(error=str(error)), 403


@collaboration.get("/reports")
def list_reports():
    return jsonify(reports=_store().list_reports())


@collaboration.get("/claims/nodes/<label>/<identifier>")
def node_claims(label: str, identifier: str):
    entity_spec(label)
    return jsonify(claims=_store().claims_for("node", label, identifier))


@collaboration.get("/claims/relationships/<relationship_type>/<identifier>")
def relationship_claims(relationship_type: str, identifier: str):
    if relationship_type not in {pattern[1] for pattern in ALLOWED_RELATIONSHIPS}:
        raise ValueError("Unsupported relationship type")
    return jsonify(claims=_store().claims_for("relationship", relationship_type, identifier))


@collaboration.post("/reports")
def create_report():
    body = _body()
    token = body.get("snapshot_token")
    if not isinstance(token, str) or len(token) > 200_000:
        raise ValueError("A signed investigation snapshot is required")
    try:
        snapshot = URLSafeTimedSerializer(current_app.secret_key, salt="cybertrace-report").loads(token, max_age=3600)
    except (BadSignature, SignatureExpired) as exc:
        raise ValueError("Investigation snapshot is invalid or expired; rerun the investigation") from exc
    return jsonify(report=_store().save_report(
        session["user"], body.get("title"), body.get("note", ""), snapshot
    )), 201


@collaboration.get("/reports/<report_id>")
def get_report(report_id: str):
    return jsonify(report=_store().get_report(report_id))


@collaboration.delete("/reports/<report_id>")
def delete_report(report_id: str):
    _store().delete_report(report_id, session["user"], current_role())
    return jsonify(deleted=True)


@collaboration.get("/evaluation/tasks")
def evaluation_tasks():
    mode = request.args.get("mode", "graph")
    return jsonify(mode=mode, tasks=tasks_for_mode(mode))


@collaboration.post("/evaluation/responses")
def evaluation_response():
    body = _body()
    mode = body.get("mode")
    if mode not in {"graph", "reference"}:
        raise ValueError("Mode must be graph or reference")
    try:
        duration = float(body.get("duration_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("duration_seconds must be a number") from exc
    if not 0 <= duration <= 3600:
        raise ValueError("duration_seconds must be between 0 and 3600")
    correct, explanation = grade(body.get("task_id"), body.get("answer"))
    result = _store().save_evaluation(
        session["user"], body["task_id"], mode, body["answer"].strip(), correct, duration
    )
    return jsonify(result=result, explanation=explanation), 201


@collaboration.get("/evaluation/summary")
def evaluation_summary():
    return jsonify(summary=_store().evaluation_summary())


@collaboration.get("/admin/users")
def list_users():
    protected = current_app.extensions["settings"].admin_username
    return jsonify(users=[{**user, "protected": user["username"] == protected} for user in _store().list_users()])


@collaboration.post("/admin/users")
def create_user():
    body = _body()
    return jsonify(user=_store().create_user(
        body.get("username"), body.get("password"), body.get("role")
    )), 201


@collaboration.patch("/admin/users/<username>")
def update_user(username: str):
    body = _body()
    if username == current_app.extensions["settings"].admin_username:
        raise ValueError("The configured administrator cannot be disabled or demoted")
    if "disabled" in body and not isinstance(body["disabled"], bool):
        raise ValueError("disabled must be true or false")
    if not set(body).issubset({"role", "disabled"}) or not body:
        raise ValueError("Provide role and/or disabled")
    return jsonify(user=_store().update_user(
        username, role=body.get("role"), disabled=body.get("disabled")
    ))


@collaboration.get("/admin/source-runs")
def source_runs():
    return jsonify(runs=_store().source_runs())


@collaboration.get("/admin/audit-events")
def audit_events():
    return jsonify(events=_store().audit_events())
