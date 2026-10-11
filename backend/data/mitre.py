"""Transform a pinned MITRE ATT&CK STIX bundle into CyberTrace records."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

ATTACK_SOURCE_NAME = "mitre-attack"
CYBERTRACE_SOURCE_NAME = "MITRE ATT&CK"


def load_stix_bundle(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        bundle = json.load(source)
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle containing an objects array")
    return bundle


def _is_active(item: dict[str, Any]) -> bool:
    return not item.get("revoked", False) and not item.get("x_mitre_deprecated", False)


def _attack_reference(item: dict[str, Any]) -> dict[str, Any]:
    for reference in item.get("external_references", []):
        if reference.get("source_name") == ATTACK_SOURCE_NAME:
            return reference
    return {}


def _external_id(item: dict[str, Any]) -> str:
    return str(_attack_reference(item).get("external_id") or item["id"])


def _rank_by_degree(
    items: list[dict[str, Any]], degree: Counter[str]
) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (-degree[item["id"]], _external_id(item), item["id"]),
    )


def _property_map(
    item: dict[str, Any], dataset: dict[str, str]
) -> tuple[str, dict[str, Any]]:
    reference = _attack_reference(item)
    external_id = _external_id(item)
    item_type = item["type"]

    if item_type == "intrusion-set":
        label = "ThreatActor"
        identifier = "actor_id"
    elif item_type in {"malware", "tool"}:
        label = "Malware"
        identifier = "malware_id"
    elif item_type == "attack-pattern":
        label = "Technique"
        identifier = "technique_id"
    else:
        raise ValueError(f"Unsupported ATT&CK object type: {item_type}")

    properties: dict[str, Any] = {
        identifier: external_id,
        "name": item.get("name", external_id),
        "description": item.get("description", ""),
        "source": CYBERTRACE_SOURCE_NAME,
        "source_id": external_id,
        "source_url": reference.get("url", dataset["download_url"]),
        "stix_id": item["id"],
        "dataset_version": dataset["release"],
        "retrieved_at": dataset["retrieved_at"],
        "is_synthetic": False,
    }

    aliases = item.get("aliases") or item.get("x_mitre_aliases")
    if aliases:
        properties["aliases"] = aliases
    if item_type in {"malware", "tool"}:
        properties["software_type"] = item_type
        if item.get("is_family") is not None:
            properties["is_family"] = item["is_family"]
    if item_type == "attack-pattern":
        phases = [
            phase.get("phase_name") for phase in item.get("kill_chain_phases", [])
        ]
        properties["categories"] = sorted({phase for phase in phases if phase})

    return label, properties


def _node_id(label: str, properties: dict[str, Any]) -> str:
    identifier_fields = {
        "ThreatActor": "actor_id",
        "Malware": "malware_id",
        "Technique": "technique_id",
    }
    return str(properties[identifier_fields[label]])


def build_subset(
    bundle: dict[str, Any],
    dataset: dict[str, str],
    *,
    group_limit: int = 25,
    software_limit: int = 40,
    technique_limit: int = 40,
) -> dict[str, Any]:
    """Build a deterministic connected subset using documented USES relationships."""
    if min(group_limit, software_limit, technique_limit) < 1:
        raise ValueError("All subset limits must be positive")

    active = [item for item in bundle["objects"] if _is_active(item)]
    objects_by_id = {item["id"]: item for item in active if "id" in item}
    groups = [item for item in active if item.get("type") == "intrusion-set"]
    software = [item for item in active if item.get("type") in {"malware", "tool"}]
    techniques = [item for item in active if item.get("type") == "attack-pattern"]

    group_ids = {item["id"] for item in groups}
    software_ids = {item["id"] for item in software}
    technique_ids = {item["id"] for item in techniques}
    uses = [
        item
        for item in active
        if item.get("type") == "relationship"
        and item.get("relationship_type") == "uses"
        and item.get("source_ref") in objects_by_id
        and item.get("target_ref") in objects_by_id
    ]

    group_degree: Counter[str] = Counter(
        relationship["source_ref"]
        for relationship in uses
        if relationship["source_ref"] in group_ids
        and relationship["target_ref"] in software_ids | technique_ids
    )
    selected_groups = _rank_by_degree(groups, group_degree)[:group_limit]
    selected_group_ids = {item["id"] for item in selected_groups}

    group_uses = [item for item in uses if item["source_ref"] in selected_group_ids]
    software_degree: Counter[str] = Counter(
        item["target_ref"] for item in group_uses if item["target_ref"] in software_ids
    )
    connected_software = [item for item in software if item["id"] in software_degree]
    selected_software = _rank_by_degree(connected_software, software_degree)[
        :software_limit
    ]
    selected_software_ids = {item["id"] for item in selected_software}

    technique_degree: Counter[str] = Counter(
        item["target_ref"]
        for item in uses
        if item["target_ref"] in technique_ids
        and item["source_ref"] in selected_group_ids | selected_software_ids
    )
    connected_techniques = [
        item for item in techniques if item["id"] in technique_degree
    ]
    selected_techniques = _rank_by_degree(connected_techniques, technique_degree)[
        :technique_limit
    ]

    selected_objects = [*selected_groups, *selected_software, *selected_techniques]
    normalized_by_stix_id: dict[str, dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    for item in selected_objects:
        label, properties = _property_map(item, dataset)
        node = {
            "label": label,
            "id": _node_id(label, properties),
            "properties": properties,
        }
        nodes.append(node)
        normalized_by_stix_id[item["id"]] = node

    relationships: list[dict[str, Any]] = []
    for item in uses:
        source = normalized_by_stix_id.get(item["source_ref"])
        target = normalized_by_stix_id.get(item["target_ref"])
        if source is None or target is None:
            continue
        if (source["label"], target["label"]) not in {
            ("ThreatActor", "Malware"),
            ("ThreatActor", "Technique"),
            ("Malware", "Technique"),
        }:
            continue
        relationships.append(
            {
                "id": item["id"],
                "type": "USES",
                "from": {"label": source["label"], "id": source["id"]},
                "to": {"label": target["label"], "id": target["id"]},
                "properties": {
                    "description": item.get("description", ""),
                    "source": CYBERTRACE_SOURCE_NAME,
                    "source_id": item["id"],
                    "source_url": dataset["download_url"],
                    "dataset_version": dataset["release"],
                    "retrieved_at": dataset["retrieved_at"],
                    "is_synthetic": False,
                },
            }
        )

    nodes.sort(key=lambda item: (item["label"], item["id"]))
    relationships.sort(key=lambda item: item["id"])
    counts = Counter(node["label"] for node in nodes)
    return {
        "metadata": {
            "source": CYBERTRACE_SOURCE_NAME,
            "dataset_version": dataset["release"],
            "retrieved_at": dataset["retrieved_at"],
            "download_url": dataset["download_url"],
            "is_synthetic": False,
            "selection": "highest documented USES degree, then ATT&CK external ID",
            "limits": {
                "ThreatActor": group_limit,
                "Malware": software_limit,
                "Technique": technique_limit,
            },
            "counts": {
                **dict(sorted(counts.items())),
                "relationships": len(relationships),
            },
        },
        "nodes": nodes,
        "relationships": relationships,
    }
