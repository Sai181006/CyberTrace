"""Persistent application records kept outside the threat-intelligence graph."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash

ROLES = {"viewer", "analyst", "admin"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


class AppStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            self.path = Path(__file__).resolve().parent.parent / self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','admin')),
                    disabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    title TEXT NOT NULL,
                    note TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS reports_created_at ON reports(created_at DESC);
                CREATE TABLE IF NOT EXISTS evaluation_responses (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    mode TEXT NOT NULL CHECK(mode IN ('graph','reference')),
                    answer TEXT NOT NULL,
                    correct INTEGER NOT NULL,
                    duration_seconds REAL NOT NULL,
                    submitted_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_runs (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    version TEXT,
                    sha256 TEXT,
                    status TEXT NOT NULL,
                    nodes INTEGER NOT NULL DEFAULT 0,
                    relationships INTEGER NOT NULL DEFAULT 0,
                    message TEXT NOT NULL DEFAULT '',
                    completed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS source_runs_latest ON source_runs(source, completed_at DESC);
                CREATE TABLE IF NOT EXISTS source_claims (
                    source TEXT NOT NULL,
                    record_kind TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    version TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL,
                    claim_json TEXT NOT NULL,
                    PRIMARY KEY(source, record_kind, record_type, record_id, version, sha256)
                );
                CREATE INDEX IF NOT EXISTS source_claims_lookup ON source_claims(record_kind, record_type, record_id);
                CREATE TABLE IF NOT EXISTS login_failures (
                    username TEXT NOT NULL,
                    address TEXT NOT NULL,
                    attempted_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS login_failures_lookup ON login_failures(username, address, attempted_at);
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_events_latest ON audit_events(created_at DESC);
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def seed_admin(self, username: str, password_hash: str) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,'admin',?) "
                "ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, "
                "role='admin', disabled=0",
                (username, password_hash, _now()),
            )

    def user(self, username: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT username,role,disabled,password_hash,created_at FROM users WHERE username=?",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        record = self.user(username)
        if not record or record["disabled"] or not check_password_hash(record["password_hash"], password):
            return None
        return {"username": record["username"], "role": record["role"]}

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT username,role,disabled,created_at FROM users ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    def create_user(self, username: str, password: str, role: str) -> dict[str, Any]:
        if not isinstance(username, str) or not username or len(username) > 64 or not all(c.isalnum() or c in "._-" for c in username):
            raise ValueError("Username must be 1–64 letters, digits, dots, underscores, or hyphens")
        if role not in ROLES:
            raise ValueError("Role must be viewer, analyst, or admin")
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")
        try:
            with self._connect() as db:
                db.execute(
                    "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                    (username, generate_password_hash(password, method="scrypt"), role, _now()),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists") from exc
        return {"username": username, "role": role, "disabled": False}

    def update_user(self, username: str, *, role: str | None = None, disabled: bool | None = None) -> dict:
        current = self.user(username)
        if not current:
            raise LookupError("User was not found")
        if role is not None and role not in ROLES:
            raise ValueError("Role must be viewer, analyst, or admin")
        with self._connect() as db:
            db.execute(
                "UPDATE users SET role=?, disabled=? WHERE username=?",
                (role or current["role"], int(disabled) if disabled is not None else current["disabled"], username),
            )
        return {"username": username, "role": role or current["role"], "disabled": bool(disabled) if disabled is not None else bool(current["disabled"])}

    def blocked_login(self, username: str, address: str) -> bool:
        cutoff = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
        with self._connect() as db:
            db.execute("DELETE FROM login_failures WHERE attempted_at < ?", (cutoff,))
            count = db.execute(
                "SELECT count(*) FROM login_failures WHERE username=? AND address=?",
                (username, address),
            ).fetchone()[0]
        return count >= 5

    def record_login(self, username: str, address: str, *, success: bool) -> None:
        with self._connect() as db:
            if success:
                db.execute("DELETE FROM login_failures WHERE username=? AND address=?", (username, address))
            else:
                db.execute(
                    "INSERT INTO login_failures(username,address,attempted_at) VALUES(?,?,?)",
                    (username, address, _now()),
                )

    def save_report(self, owner: str, title: str, note: str, snapshot: dict) -> dict:
        if not isinstance(title, str) or not 1 <= len(title.strip()) <= 160:
            raise ValueError("Report title must be 1–160 characters")
        if not isinstance(note, str) or len(note) > 5000:
            raise ValueError("Report note must be at most 5,000 characters")
        if not isinstance(snapshot, dict) or not all(
            isinstance(snapshot.get(key), dict)
            for key in ("actor", "uses", "malware", "communication", "ip", "resolution", "domain")
        ):
            raise ValueError("Report must contain the seven investigation path elements")
        encoded = json.dumps(snapshot, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > 200_000:
            raise ValueError("Report snapshot exceeds 200 KB")
        report_id, timestamp = str(uuid4()), _now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO reports VALUES(?,?,?,?,?,?,?)",
                (report_id, owner, title.strip(), note, encoded, timestamp, timestamp),
            )
        return self.get_report(report_id)

    def list_reports(self, *, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,owner,title,note,created_at,updated_at FROM reports "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_report(self, report_id: str) -> dict:
        with self._connect() as db:
            row = db.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise LookupError("Report was not found")
        report = dict(row)
        report["snapshot"] = json.loads(report.pop("snapshot_json"))
        return report

    def delete_report(self, report_id: str, username: str, role: str) -> None:
        report = self.get_report(report_id)
        if report["owner"] != username and role != "admin":
            raise PermissionError("Only the report owner or an admin can delete it")
        with self._connect() as db:
            db.execute("DELETE FROM reports WHERE id=?", (report_id,))

    def save_evaluation(self, username: str, task_id: str, mode: str, answer: str, correct: bool, duration: float) -> dict:
        response_id, timestamp = str(uuid4()), _now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO evaluation_responses VALUES(?,?,?,?,?,?,?,?)",
                (response_id, username, task_id, mode, answer, int(correct), duration, timestamp),
            )
        return {"id": response_id, "task_id": task_id, "mode": mode, "correct": correct, "duration_seconds": duration, "submitted_at": timestamp}

    def evaluation_summary(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT mode, count(*) AS responses, round(avg(correct),3) AS accuracy, "
                "round(avg(duration_seconds),1) AS avg_seconds FROM evaluation_responses GROUP BY mode ORDER BY mode"
            ).fetchall()
        return [dict(row) for row in rows]

    def record_source_run(self, source: str, version: str, sha256: str, status: str, nodes: int, relationships: int, message: str = "") -> dict:
        record = {"id": str(uuid4()), "source": source, "version": version, "sha256": sha256, "status": status, "nodes": nodes, "relationships": relationships, "message": message[:1000], "completed_at": _now()}
        with self._connect() as db:
            db.execute(
                "INSERT INTO source_runs VALUES(:id,:source,:version,:sha256,:status,:nodes,:relationships,:message,:completed_at)",
                record,
            )
        return record

    def source_runs(self, limit: int = 20) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM source_runs ORDER BY completed_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def latest_source_hash(self, source: str) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT sha256 FROM source_runs WHERE source=? AND status IN ('imported','unchanged') "
                "ORDER BY completed_at DESC LIMIT 1",
                (source,),
            ).fetchone()
        return str(row[0]) if row else None

    def latest_source_version(self, source: str) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT version FROM source_runs WHERE source=? AND status='imported' "
                "ORDER BY completed_at DESC LIMIT 1", (source,)
            ).fetchone()
        return str(row[0]) if row else None

    def record_claims(self, dataset: dict, sha256: str) -> int:
        rows = []
        for kind, records in (("node", dataset["nodes"]), ("relationship", dataset["relationships"])):
            for record in records:
                properties = record["properties"]
                rows.append((
                    str(properties["source"]), kind,
                    record["label"] if kind == "node" else record["type"],
                    str(record["id"]),
                    str(properties.get("dataset_version") or properties.get("generator_version") or "unknown"),
                    sha256,
                    str(properties.get("source_url") or ""),
                    str(properties.get("retrieved_at") or ""),
                    json.dumps(properties, ensure_ascii=False),
                ))
        with self._connect() as db:
            db.executemany(
                "INSERT OR IGNORE INTO source_claims VALUES(?,?,?,?,?,?,?,?,?)", rows
            )
        return len(rows)

    def claims_for(self, kind: str, record_type: str, record_id: str) -> list[dict]:
        if kind not in {"node", "relationship"}:
            raise ValueError("Claim kind must be node or relationship")
        with self._connect() as db:
            rows = db.execute(
                "SELECT source,record_kind,record_type,record_id,version,sha256,source_url,retrieved_at,claim_json "
                "FROM source_claims WHERE record_kind=? AND record_type=? AND record_id=? "
                "ORDER BY retrieved_at DESC LIMIT 30",
                (kind, record_type, record_id),
            ).fetchall()
        claims = []
        for row in rows:
            claim = dict(row)
            claim["properties"] = json.loads(claim.pop("claim_json"))
            claims.append(claim)
        return claims

    def record_audit(self, username: str, action: str, path: str, status: int) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT INTO audit_events VALUES(?,?,?,?,?,?)",
                (str(uuid4()), username, action, path[:300], status, _now()),
            )

    def audit_events(self, limit: int = 50) -> list[dict]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]
