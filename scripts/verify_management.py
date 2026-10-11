"""Exercise generic entity/link management and imported-data protection live."""

from __future__ import annotations

from backend.app import create_app
from backend.config import Settings

IP_ID = "SYN-FINAL-QA-IP"
DOMAIN_ID = "SYN-FINAL-QA-DOMAIN"


def _expect(response, status: int) -> dict:
    if response.status_code != status:
        raise AssertionError(
            f"Expected HTTP {status}, got {response.status_code}: "
            f"{response.get_data(as_text=True)}"
        )
    return response.get_json()


def main() -> None:
    app = create_app(Settings.from_env())
    client = app.test_client()
    with client.session_transaction() as session:
        session["user"] = app.extensions["settings"].admin_username
        session["csrf_token"] = "management-verify-token"
    headers = {"X-CSRF-Token": "management-verify-token"}
    ip_route = f"/api/entities/IP/{IP_ID}"
    domain_route = f"/api/entities/Domain/{DOMAIN_ID}"
    relationship_id: str | None = None
    try:
        # Remove only leftovers from this named synthetic verification fixture.
        client.delete(ip_route, headers=headers)
        client.delete(domain_route, headers=headers)
        metadata = _expect(client.get("/api/entity-types"), 200)
        assert len(metadata["types"]) == 7
        assert len(metadata["relationship_patterns"]) == 9
        print("PASS  Seven entity types and nine relationship patterns")

        _expect(
            client.post(
                "/api/entities",
                json={
                    "type": "IP",
                    "properties": {
                        "ip_id": IP_ID,
                        "address": "192.0.2.240",
                        "country": "Example",
                    },
                },
                headers=headers,
            ),
            201,
        )
        _expect(
            client.post(
                "/api/entities",
                json={
                    "type": "Domain",
                    "properties": {"domain_id": DOMAIN_ID, "name": "qa.example.org"},
                },
                headers=headers,
            ),
            201,
        )
        print("PASS  Create two supported synthetic entity types")

        relation = _expect(
            client.post(
                "/api/relationships",
                json={
                    "type": "RESOLVES_TO",
                    "from_type": "IP",
                    "from_id": IP_ID,
                    "to_type": "Domain",
                    "to_id": DOMAIN_ID,
                },
                headers=headers,
            ),
            201,
        )["relationship"]
        relationship_id = relation["relationship_id"]
        assert relation["is_synthetic"] is True
        fetched = _expect(client.get(f"/api/relationships/{relationship_id}"), 200)
        assert fetched["relationship"]["properties"]["source"] == "Synthetic"
        print("PASS  Create and inspect a provenance-labelled relationship")

        _expect(client.put(ip_route, json={"country": "Demo"}, headers=headers), 200)
        assert _expect(client.get(ip_route), 200)["entity"]["country"] == "Demo"
        print("PASS  Update and read a generic synthetic entity")

        blocked = client.put(
            "/api/entities/ThreatActor/G0007",
            json={"name": "Bad edit"},
            headers=headers,
        )
        _expect(blocked, 403)
        assert (
            _expect(client.get("/api/entities/ThreatActor/G0007"), 200)["entity"][
                "name"
            ]
            == "APT28"
        )
        print("PASS  Reject edits to imported real data")
    finally:
        if relationship_id:
            client.delete(f"/api/relationships/{relationship_id}", headers=headers)
        client.delete(ip_route, headers=headers)
        client.delete(domain_route, headers=headers)
        app.extensions["neo4j"].close()
    print("GENERIC MANAGEMENT READY")


if __name__ == "__main__":
    main()
