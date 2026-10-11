"""Generate deterministic, clearly marked CyberTrace demonstration data."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

GENERATOR_VERSION = "1.0.0"
DEFAULT_SEED = 302


def _provenance(seed: int) -> dict[str, Any]:
    return {
        "source": "Synthetic",
        "source_id": "CyberTrace deterministic demo generator",
        "is_synthetic": True,
        "generator_version": GENERATOR_VERSION,
        "generation_seed": seed,
    }


def _node(label: str, identifier: str, properties: dict[str, Any], seed: int) -> dict:
    return {
        "label": label,
        "id": identifier,
        "properties": {**properties, **_provenance(seed)},
    }


def _relationship(
    sequence: int,
    relationship_type: str,
    from_label: str,
    from_id: str,
    to_label: str,
    to_id: str,
    seed: int,
) -> dict:
    relationship_id = f"SYN-REL-{relationship_type}-{sequence:03d}"
    return {
        "id": relationship_id,
        "type": relationship_type,
        "from": {"label": from_label, "id": from_id},
        "to": {"label": to_label, "id": to_id},
        "properties": {**_provenance(seed), "relationship_id": relationship_id},
    }


def _ids(nodes: Iterable[dict[str, Any]], label: str) -> list[str]:
    return sorted(node["id"] for node in nodes if node["label"] == label)


def build_synthetic_dataset(
    real_subset: dict[str, Any], *, seed: int = DEFAULT_SEED
) -> dict[str, Any]:
    """Create a stable synthetic layer connected to selected real nodes."""
    actor_ids = _ids(real_subset["nodes"], "ThreatActor")
    malware_ids = _ids(real_subset["nodes"], "Malware")
    if len(actor_ids) < 12 or len(malware_ids) < 15:
        raise ValueError(
            "Real subset must contain at least 12 actors and 15 malware nodes"
        )

    organizations = [
        _node(
            "Organization",
            f"SYN-ORG-{index:03d}",
            {
                "organization_id": f"SYN-ORG-{index:03d}",
                "name": f"Synthetic Demo Organization {index:02d}",
                "industry": ["Education", "Finance", "Healthcare", "Manufacturing"][
                    (index - 1) % 4
                ],
                "country": "Synthetic",
            },
            seed,
        )
        for index in range(1, 13)
    ]
    vulnerabilities = [
        _node(
            "Vulnerability",
            f"SYN-VULN-{index:03d}",
            {
                "cve_id": f"SYN-VULN-{index:03d}",
                "name": f"Synthetic Vulnerability Scenario {index:02d}",
                "description": "Controlled demonstration record; not a real CVE.",
                "severity": ["Low", "Medium", "High", "Critical"][(index - 1) % 4],
            },
            seed,
        )
        for index in range(1, 13)
    ]

    documentation_ranges = ["192.0.2", "198.51.100", "203.0.113"]
    ips = [
        _node(
            "IP",
            f"SYN-IP-{index:03d}",
            {
                "ip_id": f"SYN-IP-{index:03d}",
                "address": (
                    f"{documentation_ranges[(index - 1) % len(documentation_ranges)]}."
                    f"{10 + index}"
                ),
                "country": "Documentation Range",
                "reputation": "Synthetic demonstration only",
            },
            seed,
        )
        for index in range(1, 16)
    ]
    example_zones = ["example.com", "example.net", "example.org"]
    domains = [
        _node(
            "Domain",
            f"SYN-DOMAIN-{index:03d}",
            {
                "domain_id": f"SYN-DOMAIN-{index:03d}",
                "name": f"c2-demo-{index:02d}.{example_zones[(index - 1) % 3]}",
                "reputation": "Synthetic demonstration only",
            },
            seed,
        )
        for index in range(1, 16)
    ]

    nodes = [*organizations, *vulnerabilities, *ips, *domains]
    relationships: list[dict[str, Any]] = []
    sequence = 1

    def add(
        relationship_type: str,
        from_label: str,
        from_id: str,
        to_label: str,
        to_id: str,
    ) -> None:
        nonlocal sequence
        relationships.append(
            _relationship(
                sequence,
                relationship_type,
                from_label,
                from_id,
                to_label,
                to_id,
                seed,
            )
        )
        sequence += 1

    for index, organization in enumerate(organizations):
        add(
            "TARGETS",
            "ThreatActor",
            actor_ids[index],
            "Organization",
            organization["id"],
        )
    for index, vulnerability in enumerate(vulnerabilities):
        add(
            "EXPLOITS",
            "ThreatActor",
            actor_ids[index],
            "Vulnerability",
            vulnerability["id"],
        )
        add(
            "EXPLOITS",
            "Malware",
            malware_ids[index],
            "Vulnerability",
            vulnerability["id"],
        )
        add(
            "AFFECTS",
            "Vulnerability",
            vulnerability["id"],
            "Organization",
            organizations[index]["id"],
        )
    for index, ip_node in enumerate(ips):
        add("COMMUNICATES_WITH", "Malware", malware_ids[index], "IP", ip_node["id"])
        add("RESOLVES_TO", "IP", ip_node["id"], "Domain", domains[index]["id"])

    return {
        "metadata": {
            "source": "Synthetic",
            "is_synthetic": True,
            "generator_version": GENERATOR_VERSION,
            "generation_seed": seed,
            "safety": {
                "ip_policy": "RFC 5737 documentation ranges only",
                "domain_policy": "IANA example domains only",
            },
            "counts": {
                "Organization": len(organizations),
                "Vulnerability": len(vulnerabilities),
                "IP": len(ips),
                "Domain": len(domains),
                "relationships": len(relationships),
            },
        },
        "nodes": nodes,
        "relationships": relationships,
    }
