"""Application configuration loaded exclusively from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


def _as_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    neo4j_uri: str
    neo4j_username: str
    neo4j_password: str
    neo4j_database: str = "neo4j"
    flask_host: str = "127.0.0.1"
    flask_port: int = 5000
    flask_debug: bool = False
    admin_username: str = "admin"
    admin_password_hash: str = ""
    secret_key: str = ""

    @classmethod
    def from_env(cls, *, require_neo4j_password: bool = True) -> "Settings":
        load_dotenv()
        password = os.getenv("NEO4J_PASSWORD", "")
        if require_neo4j_password and not password:
            raise ValueError(
                "NEO4J_PASSWORD is required; set it in the local .env file"
            )

        try:
            port = int(os.getenv("FLASK_PORT", "5000"))
        except ValueError as exc:
            raise ValueError("FLASK_PORT must be an integer") from exc

        return cls(
            neo4j_uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            neo4j_username=os.getenv("NEO4J_USERNAME", "neo4j"),
            neo4j_password=password,
            neo4j_database=os.getenv("NEO4J_DATABASE", "neo4j"),
            flask_host=os.getenv("FLASK_HOST", "127.0.0.1"),
            flask_port=port,
            flask_debug=_as_bool(os.getenv("FLASK_DEBUG")),
            admin_username=os.getenv("CYBERTRACE_ADMIN_USERNAME", "admin"),
            admin_password_hash=os.getenv("CYBERTRACE_ADMIN_PASSWORD_HASH", ""),
            secret_key=os.getenv("CYBERTRACE_SECRET_KEY", ""),
        )
