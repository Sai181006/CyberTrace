from __future__ import annotations

import ipaddress

from backend.data.synthetic import build_synthetic_dataset


def _real_subset() -> dict:
    actors = [{"label": "ThreatActor", "id": f"G{index:04d}"} for index in range(1, 13)]
    malware = [{"label": "Malware", "id": f"S{index:04d}"} for index in range(1, 16)]
    return {"nodes": [*actors, *malware], "relationships": []}


def test_synthetic_generation_is_deterministic_and_marked() -> None:
    first = build_synthetic_dataset(_real_subset(), seed=302)
    second = build_synthetic_dataset(_real_subset(), seed=302)

    assert first == second
    assert len(first["nodes"]) == 54
    assert len(first["relationships"]) == 78
    assert all(node["properties"]["is_synthetic"] is True for node in first["nodes"])
    assert all(node["properties"]["source"] == "Synthetic" for node in first["nodes"])
    assert all(
        relationship["properties"]["is_synthetic"] is True
        for relationship in first["relationships"]
    )


def test_synthetic_infrastructure_uses_reserved_values() -> None:
    dataset = build_synthetic_dataset(_real_subset())
    allowed_networks = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    addresses = [
        ipaddress.ip_address(node["properties"]["address"])
        for node in dataset["nodes"]
        if node["label"] == "IP"
    ]
    domains = [
        node["properties"]["name"]
        for node in dataset["nodes"]
        if node["label"] == "Domain"
    ]

    assert all(
        any(address in network for network in allowed_networks) for address in addresses
    )
    assert all(
        domain.endswith((".example.com", ".example.net", ".example.org"))
        for domain in domains
    )


def test_six_distinct_relationship_types_exist_across_layers() -> None:
    dataset = build_synthetic_dataset(_real_subset())
    synthetic_types = {item["type"] for item in dataset["relationships"]}

    assert synthetic_types | {"USES"} == {
        "USES",
        "TARGETS",
        "EXPLOITS",
        "AFFECTS",
        "COMMUNICATES_WITH",
        "RESOLVES_TO",
    }
