"""Validation rules that keep CyberTrace real and synthetic data trustworthy."""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from typing import Any

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
EXAMPLE_SUFFIXES = (".example.com", ".example.net", ".example.org")
REAL_PROVENANCE = {
    "source",
    "source_id",
    "source_url",
    "dataset_version",
    "retrieved_at",
    "is_synthetic",
}
SYNTHETIC_PROVENANCE = {
    "source",
    "source_id",
    "generator_version",
    "generation_seed",
    "is_synthetic",
}


def _require_fields(
    properties: dict[str, Any], required: set[str], context: str
) -> None:
    missing = sorted(required - properties.keys())
    if missing:
        raise ValueError(
            f"{context} is missing provenance fields: {', '.join(missing)}"
        )


def _validate_provenance(records: list[dict[str, Any]], *, synthetic: bool) -> None:
    required = SYNTHETIC_PROVENANCE if synthetic else REAL_PROVENANCE
    expected_source = "Synthetic" if synthetic else "MITRE ATT&CK"
    for record in records:
        properties = record["properties"]
        context = f"record {record['id']}"
        _require_fields(properties, required, context)
        if properties["is_synthetic"] is not synthetic:
            raise ValueError(f"{context} has an incorrect is_synthetic flag")
        if properties["source"] != expected_source:
            raise ValueError(f"{context} has an incorrect source")


def _validate_synthetic_infrastructure(nodes: list[dict[str, Any]]) -> None:
    for node in nodes:
        if node["label"] == "IP":
            address = ipaddress.ip_address(node["properties"]["address"])
            if not any(address in network for network in DOCUMENTATION_NETWORKS):
                raise ValueError(
                    f"Synthetic IP {address} is outside documentation ranges"
                )
        if node["label"] == "Domain":
            domain = node["properties"]["name"]
            if not domain.endswith(EXAMPLE_SUFFIXES):
                raise ValueError(
                    f"Synthetic domain {domain} is outside example domains"
                )


def validate_datasets(
    real_dataset: dict[str, Any], synthetic_dataset: dict[str, Any]
) -> dict[str, Any]:
    real_nodes = real_dataset["nodes"]
    real_relationships = real_dataset["relationships"]
    synthetic_nodes = synthetic_dataset["nodes"]
    synthetic_relationships = synthetic_dataset["relationships"]
    _validate_provenance(real_nodes + real_relationships, synthetic=False)
    _validate_provenance(synthetic_nodes + synthetic_relationships, synthetic=True)
    _validate_synthetic_infrastructure(synthetic_nodes)

    nodes = real_nodes + synthetic_nodes
    relationships = real_relationships + synthetic_relationships
    keys = [(node["label"], node["id"]) for node in nodes]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate node label/ID pairs detected")

    node_keys = set(keys)
    relationship_ids = [item["id"] for item in relationships]
    if len(relationship_ids) != len(set(relationship_ids)):
        raise ValueError("Duplicate relationship IDs detected")
    for relationship in relationships:
        start = (relationship["from"]["label"], relationship["from"]["id"])
        end = (relationship["to"]["label"], relationship["to"]["id"])
        if start not in node_keys or end not in node_keys:
            raise ValueError(
                f"Relationship {relationship['id']} has a missing endpoint"
            )

    label_counts = Counter(node["label"] for node in nodes)
    relationship_counts = Counter(item["type"] for item in relationships)
    if len(nodes) < 100:
        raise ValueError("Dataset must contain at least 100 nodes")
    if len(label_counts) < 5:
        raise ValueError("Dataset must contain at least 5 node labels")
    if len(relationship_counts) < 6:
        raise ValueError("Dataset must contain at least 6 relationship types")

    edges: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for relationship in relationships:
        start = (relationship["from"]["label"], relationship["from"]["id"])
        end = (relationship["to"]["label"], relationship["to"]["id"])
        edges[start].append((relationship["type"], *end))
    has_investigation_path = any(
        relationship_type == "USES"
        and target_label == "Malware"
        and any(
            next_type == "COMMUNICATES_WITH"
            and next_label == "IP"
            and any(
                last_type == "RESOLVES_TO" and last_label == "Domain"
                for last_type, last_label, _ in edges[(next_label, next_id)]
            )
            for next_type, next_label, next_id in edges[(target_label, target_id)]
        )
        for (source_label, _), outgoing in edges.items()
        if source_label == "ThreatActor"
        for relationship_type, target_label, target_id in outgoing
    )
    if not has_investigation_path:
        raise ValueError("No ThreatActor -> Malware -> IP -> Domain path exists")

    return {
        "status": "PASS",
        "nodes": len(nodes),
        "relationships": len(relationships),
        "labels": dict(sorted(label_counts.items())),
        "relationship_types": dict(sorted(relationship_counts.items())),
        "real_nodes": len(real_nodes),
        "synthetic_nodes": len(synthetic_nodes),
        "multi_hop_investigation": True,
    }
