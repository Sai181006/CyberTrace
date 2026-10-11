from backend.app import create_app
from backend.config import Settings
from werkzeug.security import generate_password_hash


class FakeDatabase:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def verify_connectivity(self) -> None:
        return None

    def close(self) -> None:
        return None


def settings() -> Settings:
    return Settings(
        "bolt://test:7687",
        "neo4j",
        "secret",
        admin_password_hash=generate_password_hash("test-password", method="scrypt"),
        secret_key="test-only-secret-key",
    )


def test_api_root() -> None:
    app = create_app(settings(), database_factory=FakeDatabase)
    client = app.test_client()
    assert client.get("/api").status_code == 401
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "test-password"}
    )
    assert login.status_code == 200

    response = client.get("/api")

    assert response.status_code == 200
    assert response.get_json()["name"] == "CyberTrace API"


def test_health_checks_database() -> None:
    app = create_app(settings(), database_factory=FakeDatabase)

    response = app.test_client().get("/api/health")

    assert response.status_code == 200
    assert response.get_json() == {"database": "connected", "status": "healthy"}


def test_frontend_is_served() -> None:
    app = create_app(settings(), database_factory=FakeDatabase)

    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b"CyberTrace" in response.data


def test_authentication_and_csrf_lifecycle() -> None:
    app = create_app(settings(), database_factory=FakeDatabase)
    client = app.test_client()
    assert client.get("/api/auth/session").get_json() == {"authenticated": False}
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        ).status_code
        == 401
    )
    assert client.get("/api/dashboard").status_code == 401

    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "test-password"}
    )
    token = login.get_json()["csrf_token"]
    assert client.get("/api/auth/session").get_json()["authenticated"] is True
    assert client.post("/api/entities", json={}).status_code == 403
    assert (
        client.post(
            "/api/entities", json={}, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/entities", json={}, headers={"X-CSRF-Token": token}
        ).status_code
        == 400
    )
    assert (
        client.post("/api/auth/logout", headers={"X-CSRF-Token": token}).status_code
        == 200
    )
    assert client.get("/api").status_code == 401


def test_missing_auth_configuration_fails_closed() -> None:
    app_settings = Settings("bolt://test:7687", "neo4j", "secret")
    try:
        create_app(app_settings, database_factory=FakeDatabase)
    except RuntimeError as exc:
        assert "CYBERTRACE_SECRET_KEY" in str(exc)
    else:
        raise AssertionError("Missing administrator settings must fail closed")
