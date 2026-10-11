"""Allowlisted entity metadata for safe dynamic Cypher construction."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EntitySpec:
    label: str
    identifier: str
    searchable: str
    mutable: frozenset[str]


ENTITY_SPECS = {
    "ThreatActor": EntitySpec(
        "ThreatActor",
        "actor_id",
        "name",
        frozenset({"name", "description", "aliases"}),
    ),
    "Malware": EntitySpec(
        "Malware",
        "malware_id",
        "name",
        frozenset(
            {
                "name",
                "family",
                "description",
                "severity",
                "aliases",
                "software_type",
                "is_family",
            }
        ),
    ),
    "Technique": EntitySpec(
        "Technique",
        "technique_id",
        "name",
        frozenset({"name", "description", "category", "categories"}),
    ),
    "Vulnerability": EntitySpec(
        "Vulnerability",
        "cve_id",
        "cve_id",
        frozenset({"name", "description", "severity"}),
    ),
    "IP": EntitySpec(
        "IP",
        "ip_id",
        "address",
        frozenset({"address", "country", "reputation"}),
    ),
    "Domain": EntitySpec(
        "Domain",
        "domain_id",
        "name",
        frozenset({"name", "reputation"}),
    ),
    "Organization": EntitySpec(
        "Organization",
        "organization_id",
        "name",
        frozenset({"name", "industry", "country"}),
    ),
}


def entity_spec(label: str) -> EntitySpec:
    try:
        return ENTITY_SPECS[label]
    except KeyError as exc:
        raise ValueError(f"Unsupported entity type: {label}") from exc
