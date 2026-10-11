"""Idempotent Neo4j loading for validated CyberTrace datasets."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from neo4j import ManagedTransaction

from backend.db import Neo4jDatabase
from backend.schema import NODE_IDENTIFIERS

RelationshipPattern = tuple[str, str, str]

ALLOWED_RELATIONSHIPS: set[RelationshipPattern] = {
    ("ThreatActor", "USES", "Malware"),
    ("ThreatActor", "USES", "Technique"),
    ("Malware", "USES", "Technique"),
    ("ThreatActor", "TARGETS", "Organization"),
    ("ThreatActor", "EXPLOITS", "Vulnerability"),
    ("Malware", "EXPLOITS", "Vulnerability"),
    ("Malware", "COMMUNICATES_WITH", "IP"),
    ("IP", "RESOLVES_TO", "Domain"),
    ("Vulnerability", "AFFECTS", "Organization"),
}


def node_query(label: str) -> str:
    try:
        identifier = NODE_IDENTIFIERS[label]
    except KeyError as exc:
        raise ValueError(f"Unsupported node label: {label}") from exc
    return (
        "UNWIND $rows AS row "
        f"MERGE (n:{label} {{{identifier}: row.id}}) "
        "SET n += row.properties "
        "RETURN count(n) AS processed"
    )


def relationship_query(pattern: RelationshipPattern) -> str:
    if pattern not in ALLOWED_RELATIONSHIPS:
        raise ValueError(f"Unsupported relationship pattern: {pattern}")
    from_label, relationship_type, to_label = pattern
    from_identifier = NODE_IDENTIFIERS[from_label]
    to_identifier = NODE_IDENTIFIERS[to_label]
    return (
        "UNWIND $rows AS row "
        f"MATCH (source:{from_label} {{{from_identifier}: row.from_id}}) "
        f"MATCH (target:{to_label} {{{to_identifier}: row.to_id}}) "
        f"MERGE (source)-[r:{relationship_type} "
        "{relationship_id: row.id}]->(target) "
        "SET r += row.properties "
        "RETURN count(r) AS processed"
    )


def _run_batch(tx: ManagedTransaction, query: str, rows: list[dict[str, Any]]) -> int:
    record = tx.run(query, rows=rows).single(strict=True)
    return int(record["processed"])


def load_datasets(
    database: Neo4jDatabase, datasets: Iterable[dict[str, Any]]
) -> dict[str, int]:
    nodes_by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    relationships_by_pattern: dict[RelationshipPattern, list[dict[str, Any]]] = (
        defaultdict(list)
    )

    for dataset in datasets:
        for node in dataset["nodes"]:
            if node["label"] not in NODE_IDENTIFIERS:
                raise ValueError(f"Unsupported node label: {node['label']}")
            nodes_by_label[node["label"]].append(
                {"id": node["id"], "properties": node["properties"]}
            )
        for relationship in dataset["relationships"]:
            pattern = (
                relationship["from"]["label"],
                relationship["type"],
                relationship["to"]["label"],
            )
            if pattern not in ALLOWED_RELATIONSHIPS:
                raise ValueError(f"Unsupported relationship pattern: {pattern}")
            relationships_by_pattern[pattern].append(
                {
                    "id": relationship["id"],
                    "from_id": relationship["from"]["id"],
                    "to_id": relationship["to"]["id"],
                    "properties": relationship["properties"],
                }
            )

    node_count = 0
    for label in sorted(nodes_by_label):
        query = node_query(label)
        rows = nodes_by_label[label]
        node_count += database.execute_write(
            lambda tx, query=query, rows=rows: _run_batch(tx, query, rows)
        )

    relationship_count = 0
    for pattern in sorted(relationships_by_pattern):
        query = relationship_query(pattern)
        rows = relationships_by_pattern[pattern]
        relationship_count += database.execute_write(
            lambda tx, query=query, rows=rows: _run_batch(tx, query, rows)
        )

    return {
        "nodes_processed": node_count,
        "relationships_processed": relationship_count,
    }
