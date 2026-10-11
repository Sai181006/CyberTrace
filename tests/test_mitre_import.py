from __future__ import annotations

from backend.data.mitre import build_subset


def _object(item_type: str, item_id: str, external_id: str, name: str) -> dict:
    return {
        "type": item_type,
        "id": item_id,
        "name": name,
        "description": f"Description for {name}",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": external_id,
                "url": f"https://attack.mitre.org/{external_id}",
            }
        ],
    }


def _relationship(item_id: str, source: str, target: str) -> dict:
    return {
        "type": "relationship",
        "id": item_id,
        "relationship_type": "uses",
        "source_ref": source,
        "target_ref": target,
    }


def test_build_subset_preserves_real_provenance() -> None:
    actor = _object("intrusion-set", "intrusion-set--1", "G0001", "Actor One")
    malware = _object("malware", "malware--1", "S0001", "Malware One")
    technique = _object("attack-pattern", "attack-pattern--1", "T0001", "Technique One")
    bundle = {
        "type": "bundle",
        "objects": [
            actor,
            malware,
            technique,
            _relationship("relationship--1", actor["id"], malware["id"]),
            _relationship("relationship--2", malware["id"], technique["id"]),
        ],
    }
    dataset = {
        "release": "19.2",
        "retrieved_at": "2026-09-25T11:10:15Z",
        "download_url": "https://example.test/enterprise-attack-19.2.json",
    }

    subset = build_subset(
        bundle, dataset, group_limit=1, software_limit=1, technique_limit=1
    )

    assert len(subset["nodes"]) == 3
    assert len(subset["relationships"]) == 2
    assert all(node["properties"]["is_synthetic"] is False for node in subset["nodes"])
    assert all(
        node["properties"]["source"] == "MITRE ATT&CK" for node in subset["nodes"]
    )
    assert all(
        relationship["properties"]["is_synthetic"] is False
        for relationship in subset["relationships"]
    )


def test_revoked_objects_are_excluded() -> None:
    actor = _object("intrusion-set", "intrusion-set--1", "G0001", "Actor One")
    malware = _object("malware", "malware--1", "S0001", "Malware One")
    malware["revoked"] = True
    bundle = {
        "type": "bundle",
        "objects": [
            actor,
            malware,
            _relationship("relationship--1", actor["id"], malware["id"]),
        ],
    }
    dataset = {
        "release": "19.2",
        "retrieved_at": "2026-09-25T11:10:15Z",
        "download_url": "https://example.test/enterprise-attack-19.2.json",
    }

    subset = build_subset(bundle, dataset)

    assert subset["nodes"] == [
        {
            "label": "ThreatActor",
            "id": "G0001",
            "properties": subset["nodes"][0]["properties"],
        }
    ]
    assert subset["relationships"] == []
