"""Exercise the full Review 2 CRUD workflow through the Flask API."""

from __future__ import annotations

from backend.app import create_app
from backend.config import Settings

DEMO_ID = "SYN-REVIEW-DEMO"


def _expect(response, status: int) -> dict:
    if response.status_code != status:
        raise RuntimeError(
            f"Expected HTTP {status}, got {response.status_code}: {response.get_data(as_text=True)}"
        )
    return response.get_json()


def main() -> None:
    app = create_app(Settings.from_env())
    client = app.test_client()
    with client.session_transaction() as session:
        session["user"] = app.extensions["settings"].admin_username
        session["csrf_token"] = "verification-token"
    headers = {"X-CSRF-Token": "verification-token"}
    try:
        client.delete(f"/api/entities/Malware/{DEMO_ID}", headers=headers)

        created = _expect(
            client.post(
                "/api/entities",
                json={
                    "type": "Malware",
                    "properties": {
                        "malware_id": DEMO_ID,
                        "name": "ReviewDemoMalware",
                        "description": "Synthetic record for the Review 2 CRUD demonstration.",
                        "severity": "Medium",
                    },
                },
                headers=headers,
            ),
            201,
        )["entity"]
        assert created["is_synthetic"] is True
        print("PASS  Create synthetic malware")

        read = _expect(client.get(f"/api/entities/Malware/{DEMO_ID}"), 200)["entity"]
        assert read["name"] == "ReviewDemoMalware"
        print("PASS  Read malware by stable ID")

        updated = _expect(
            client.put(
                f"/api/entities/Malware/{DEMO_ID}",
                json={
                    "severity": "High",
                    "description": "Updated during CRUD verification.",
                },
                headers=headers,
            ),
            200,
        )["entity"]
        assert updated["severity"] == "High"
        print("PASS  Update malware properties")

        search = _expect(
            client.get("/api/entities/search?q=ReviewDemoMalware&type=Malware"), 200
        )["results"]
        assert any(row["entity"]["malware_id"] == DEMO_ID for row in search)
        print("PASS  Search updated malware")

        deleted = _expect(
            client.delete(f"/api/entities/Malware/{DEMO_ID}", headers=headers), 200
        )["deleted"]
        assert deleted["malware_id"] == DEMO_ID
        print("PASS  Delete malware and attached relationships safely")

        _expect(client.get(f"/api/entities/Malware/{DEMO_ID}"), 404)
        print("PASS  Verify deletion")
        print("CRUD WORKFLOW READY")
    finally:
        app.extensions["neo4j"].close()


if __name__ == "__main__":
    main()
