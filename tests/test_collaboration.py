from __future__ import annotations

from pathlib import Path

from backend.app import create_app
from backend.config import Settings
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash


class FakeDatabase:
    def __init__(self, settings: Settings) -> None:
        pass

    def verify_connectivity(self) -> None:
        pass

    def close(self) -> None:
        pass


def _app(tmp_path: Path):
    settings = Settings(
        "bolt://test:7687", "neo4j", "secret",
        admin_password_hash=generate_password_hash("admin-password-123", method="scrypt"),
        secret_key="test-secret-key-with-sufficient-length",
        app_database_path=str(tmp_path / "shared.sqlite3"),
    )
    return create_app(settings, database_factory=FakeDatabase)


def _login(client, username: str, password: str) -> str:
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.get_json()["csrf_token"]


def _path() -> dict:
    return {key: {"name": key, "source": "Synthetic", "is_synthetic": True} for key in (
        "actor", "uses", "malware", "communication", "ip", "resolution", "domain"
    )}


def test_roles_and_reports_are_shared_across_sessions(tmp_path: Path) -> None:
    app = _app(tmp_path)
    admin, analyst, viewer = app.test_client(), app.test_client(), app.test_client()
    admin_token = _login(admin, "admin", "admin-password-123")
    for username, role in (("analyst1", "analyst"), ("viewer1", "viewer")):
        response = admin.post(
            "/api/admin/users", json={"username": username, "password": "teammate-password-123", "role": role},
            headers={"X-CSRF-Token": admin_token},
        )
        assert response.status_code == 201
    analyst_token = _login(analyst, "analyst1", "teammate-password-123")
    viewer_token = _login(viewer, "viewer1", "teammate-password-123")
    save_token = URLSafeTimedSerializer(app.secret_key, salt="cybertrace-report").dumps(_path())
    response = analyst.post(
        "/api/reports", json={"title": "APT28 example", "note": "Mixed provenance", "snapshot_token": save_token},
        headers={"X-CSRF-Token": analyst_token},
    )
    assert response.status_code == 201
    report_id = response.get_json()["report"]["id"]
    assert viewer.get("/api/reports").get_json()["reports"][0]["id"] == report_id
    assert viewer.get(f"/api/reports/{report_id}").get_json()["report"]["snapshot"]["actor"]["name"] == "actor"
    assert viewer.post("/api/reports", json={}, headers={"X-CSRF-Token": viewer_token}).status_code == 403
    assert analyst.post("/api/reports", json={"title": "Forged", "snapshot_token": save_token + "x"}, headers={"X-CSRF-Token": analyst_token}).status_code == 400
    assert viewer.delete(f"/api/reports/{report_id}", headers={"X-CSRF-Token": viewer_token}).status_code == 403
    assert analyst.delete(f"/api/reports/{report_id}", headers={"X-CSRF-Token": analyst_token}).status_code == 200
    assert viewer.get(f"/api/reports/{report_id}").status_code == 404
    assert viewer.get("/api/admin/users").status_code == 403


def test_evaluation_records_time_and_grades_without_leaking_answers(tmp_path: Path) -> None:
    app = _app(tmp_path)
    client = app.test_client()
    token = _login(client, "admin", "admin-password-123")
    graph_tasks = client.get("/api/evaluation/tasks?mode=graph").get_json()["tasks"]
    reference_tasks = client.get("/api/evaluation/tasks?mode=reference").get_json()["tasks"]
    assert "answers" not in graph_tasks[0]
    assert "reference_context" not in graph_tasks[0]
    assert "reference_context" in reference_tasks[0]
    response = client.post(
        "/api/evaluation/responses",
        json={"task_id": "apt28-id", "mode": "graph", "answer": "G0007", "duration_seconds": 19.2},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 201
    assert response.get_json()["result"]["correct"] is True
    assert client.get("/api/evaluation/summary").get_json()["summary"][0]["accuracy"] == 1.0


def test_login_rate_limit_and_security_headers(tmp_path: Path) -> None:
    app = _app(tmp_path)
    client = app.test_client()
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin", "password": "admin-password-123"}).status_code == 429
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]


def test_https_mode_requires_secure_transport_and_cookie(tmp_path: Path) -> None:
    settings = Settings(
        "bolt://test:7687", "neo4j", "secret",
        admin_password_hash=generate_password_hash("admin-password-123", method="scrypt"),
        secret_key="a-long-test-only-secret-key-for-https-mode",
        app_database_path=str(tmp_path / "secure.sqlite3"),
        require_https=True,
        trusted_hosts=("cybertrace.example.org",),
    )
    app = create_app(settings, database_factory=FakeDatabase)
    client = app.test_client()
    assert client.get("/api/health", base_url="http://cybertrace.example.org").status_code == 403
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin-password-123"},
        base_url="https://cybertrace.example.org",
    )
    assert login.status_code == 200
    assert "Secure" in login.headers["Set-Cookie"]
    assert "Strict-Transport-Security" in login.headers
