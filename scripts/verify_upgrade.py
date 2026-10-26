"""Exercise the upgraded HTTP flows against live Neo4j without changing graph data."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from werkzeug.security import generate_password_hash

from backend.app import create_app
from backend.config import Settings


def main() -> None:
    with TemporaryDirectory(prefix="cybertrace-upgrade-") as directory:
        base = Settings.from_env()
        settings = replace(
            base,
            admin_password_hash=generate_password_hash("verification-only-password", method="scrypt"),
            secret_key="verification-only-secret-key-with-sufficient-length",
            app_database_path=str(Path(directory) / "app.sqlite3"),
            require_https=False,
            trusted_proxy_count=0,
            trusted_hosts=("localhost", "127.0.0.1"),
        )
        app = create_app(settings)
        try:
            fixture = Path(__file__).resolve().parent.parent / "data" / "processed" / "mitre-attack-subset.json"
            app.extensions["app_store"].record_claims(json.loads(fixture.read_text(encoding="utf-8")), "verification-fixture")
            admin = app.test_client()
            login = admin.post("/api/auth/login", json={"username": settings.admin_username, "password": "verification-only-password"})
            assert login.status_code == 200, login.get_json()
            token = login.get_json()["csrf_token"]
            graph = admin.get("/api/graph/entity/ThreatActor/G0007?limit=50&neighbor_type=Malware&provenance=real")
            assert graph.status_code == 200 and graph.get_json()["total"] > 0
            claims = admin.get("/api/claims/nodes/ThreatActor/G0007")
            assert claims.status_code == 200 and claims.get_json()["claims"][0]["source"] == "MITRE ATT&CK"
            cve_search = admin.get("/api/entities/search?q=SYN-VULN-001&type=Vulnerability")
            assert cve_search.status_code == 200 and cve_search.get_json()["results"][0]["entity"]["cve_id"] == "SYN-VULN-001"
            investigation = admin.get("/api/investigations/actor-investigation?value=APT28&limit=1")
            assert investigation.status_code == 200 and investigation.get_json()["results"]
            signed = investigation.get_json()["results"][0]["_save_token"]
            report = admin.post(
                "/api/reports",
                json={"title": "Verification report", "note": "Mixed provenance", "snapshot_token": signed},
                headers={"X-CSRF-Token": token},
            )
            assert report.status_code == 201, report.get_json()
            created = admin.post(
                "/api/admin/users",
                json={"username": "verification-viewer", "password": "verification-viewer-password", "role": "viewer"},
                headers={"X-CSRF-Token": token},
            )
            assert created.status_code == 201, created.get_json()
            viewer = app.test_client()
            assert viewer.post("/api/auth/login", json={"username": "verification-viewer", "password": "verification-viewer-password"}).status_code == 200
            assert viewer.get("/api/reports").get_json()["reports"][0]["title"] == "Verification report"
            task = admin.get("/api/evaluation/tasks?mode=graph")
            assert task.status_code == 200 and task.get_json()["tasks"]
            answer = admin.post(
                "/api/evaluation/responses",
                json={"task_id": "shared-technique", "mode": "graph", "answer": "T1003.001", "duration_seconds": 12.5},
                headers={"X-CSRF-Token": token},
            )
            assert answer.status_code == 201 and answer.get_json()["result"]["correct"]
            assert admin.get("/api/admin/audit-events").get_json()["events"]
            print("PASS  50-link graph filter, CVE search, source history, signed shared report, viewer access, evaluation, audit")
            print("CYBERTRACE UPGRADE READY")
        finally:
            app.extensions["neo4j"].close()


if __name__ == "__main__":
    main()
