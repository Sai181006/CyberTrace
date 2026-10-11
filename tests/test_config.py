from __future__ import annotations

import pytest

from backend.config import Settings


def test_settings_require_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("backend.config.load_dotenv", lambda: None)
    monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
    monkeypatch.setenv("FLASK_PORT", "5000")

    with pytest.raises(ValueError, match="NEO4J_PASSWORD"):
        Settings.from_env()


def test_settings_parse_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("backend.config.load_dotenv", lambda: None)
    monkeypatch.setenv("NEO4J_PASSWORD", "test-secret")
    monkeypatch.setenv("FLASK_PORT", "5050")
    monkeypatch.setenv("FLASK_DEBUG", "true")

    settings = Settings.from_env()

    assert settings.neo4j_password == "test-secret"
    assert settings.flask_port == 5050
    assert settings.flask_debug is True
