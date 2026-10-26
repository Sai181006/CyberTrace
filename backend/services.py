"""Neo4j-backed CRUD, search, dashboard, and graph services."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from .data.loader import ALLOWED_RELATIONSHIPS
from .db import Neo4jDatabase
from .entities import ENTITY_SPECS, EntitySpec, entity_spec


class EntityNotFoundError(LookupError):
    pass


class EntityConflictError(RuntimeError):
    pass


class EntityReadOnlyError(PermissionError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _clean_properties(
    spec: EntitySpec, properties: dict[str, Any], *, create: bool
) -> dict:
    allowed = spec.mutable | ({spec.identifier} if create else set())
    unknown = sorted(set(properties) - allowed)
    if unknown:
        raise ValueError(
            f"Unsupported properties for {spec.label}: {', '.join(unknown)}"
        )
    cleaned = {key: value for key, value in properties.items() if value is not None}
    for key, value in cleaned.items():
        if key in {"aliases", "categories"}:
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise ValueError(f"{key} must be an array of strings")
        elif key == "is_family":
            if not isinstance(value, bool):
                raise ValueError("is_family must be true or false")
        elif not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
    if create and (
        not isinstance(cleaned.get(spec.identifier), str)
        or len(cleaned[spec.identifier]) > 128
    ):
        raise ValueError(
            f"{spec.identifier} must be a string of at most 128 characters"
        )
    if create and not str(cleaned.get(spec.identifier, "")).strip():
        raise ValueError(f"{spec.identifier} is required")
    if not cleaned:
        raise ValueError("At least one property is required")
    return cleaned


def create_entity(
    database: Neo4jDatabase, label: str, properties: dict[str, Any]
) -> dict:
    spec = entity_spec(label)
    cleaned = _clean_properties(spec, properties, create=True)
    created_at = _now()
    identifier = cleaned[spec.identifier]
    payload = {
        **cleaned,
        "source": "Synthetic",
        "source_id": f"manual:{label}:{identifier}",
        "is_synthetic": True,
        "generator_version": "manual-crud-v1",
        "generation_seed": 0,
        "created_at": created_at,
        "updated_at": created_at,
    }
    query = (
        f"MERGE (n:{spec.label} {{{spec.identifier}: $identifier}}) "
        "ON CREATE SET n = $properties "
        "RETURN properties(n) AS entity, n.created_at = $created_at AS created"
    )
    row = database.write_query(
        query,
        {"identifier": identifier, "properties": payload, "created_at": created_at},
    )[0]
    if not row["created"]:
        raise EntityConflictError(f"{label} {identifier} already exists")
    return row["entity"]


def get_entity(database: Neo4jDatabase, label: str, identifier: str) -> dict:
    spec = entity_spec(label)
    rows = database.read_query(
        f"MATCH (n:{spec.label} {{{spec.identifier}: $identifier}}) "
        "RETURN properties(n) AS entity",
        {"identifier": identifier},
    )
    if not rows:
        raise EntityNotFoundError(f"{label} {identifier} was not found")
    return rows[0]["entity"]


def update_entity(
    database: Neo4jDatabase, label: str, identifier: str, changes: dict[str, Any]
) -> dict:
    spec = entity_spec(label)
    current = get_entity(database, label, identifier)
    if not current.get("is_synthetic"):
        raise EntityReadOnlyError("Real imported entities are read-only")
    cleaned = _clean_properties(spec, changes, create=False)
    cleaned["updated_at"] = _now()
    rows = database.write_query(
        f"MATCH (n:{spec.label} {{{spec.identifier}: $identifier}}) "
        "WHERE n.is_synthetic = true "
        "SET n += $changes RETURN properties(n) AS entity",
        {"identifier": identifier, "changes": cleaned},
    )
    if not rows:
        raise EntityNotFoundError(f"{label} {identifier} was not found")
    return rows[0]["entity"]


def delete_entity(database: Neo4jDatabase, label: str, identifier: str) -> dict:
    spec = entity_spec(label)
    current = get_entity(database, label, identifier)
    if not current.get("is_synthetic"):
        raise EntityReadOnlyError("Real imported entities are read-only")
    rows = database.write_query(
        f"MATCH (n:{spec.label} {{{spec.identifier}: $identifier}}) "
        "WHERE n.is_synthetic = true "
        "WITH n, properties(n) AS deleted DETACH DELETE n RETURN deleted",
        {"identifier": identifier},
    )
    if not rows:
        raise EntityNotFoundError(f"{label} {identifier} was not found")
    return rows[0]["deleted"]


def search_entities(
    database: Neo4jDatabase, term: str, label: str | None = None, *, limit: int = 50
) -> list[dict]:
    if not term.strip():
        raise ValueError("Search term is required")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    label_clause = ""
    if label:
        label_clause = f":{entity_spec(label).label}"
    query = (
        f"MATCH (n{label_clause}) "
        "WHERE toLower(coalesce(n.name, n.address, n.cve_id, '')) "
        "CONTAINS toLower($term) "
        "RETURN labels(n)[0] AS type, properties(n) AS entity "
        "ORDER BY coalesce(n.name, n.address, n.cve_id) LIMIT $limit"
    )
    return database.read_query(query, {"term": term.strip(), "limit": limit})


def dashboard(database: Neo4jDatabase) -> dict:
    label_rows = database.read_query(
        "MATCH (n) UNWIND labels(n) AS label "
        "RETURN label, count(*) AS count ORDER BY label"
    )
    totals = database.read_query(
        "MATCH (n) WITH count(n) AS nodes "
        "OPTIONAL MATCH ()-[r]->() RETURN nodes, count(r) AS relationships"
    )[0]
    provenance = database.read_query(
        "MATCH (n) RETURN n.is_synthetic AS is_synthetic, count(*) AS count"
    )
    return {
        **totals,
        "labels": {row["label"]: row["count"] for row in label_rows},
        "provenance": {
            "synthetic" if row["is_synthetic"] else "real": row["count"]
            for row in provenance
        },
    }


def entity_graph(
    database: Neo4jDatabase,
    label: str,
    identifier: str,
    *,
    limit: int = 12,
    offset: int = 0,
    relationship_type: str | None = None,
    provenance: str = "all",
) -> dict:
    spec = entity_spec(label)
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    allowed_types = {pattern[1] for pattern in ALLOWED_RELATIONSHIPS}
    if relationship_type and relationship_type not in allowed_types:
        raise ValueError("Unsupported relationship type")
    if provenance not in {"all", "real", "synthetic"}:
        raise ValueError("provenance must be all, real, or synthetic")
    centers = database.read_query(
        f"MATCH (center:{spec.label} {{{spec.identifier}: $identifier}}) "
        "RETURN elementId(center) AS center_id, properties(center) AS center, "
        "labels(center)[0] AS center_type",
        {"identifier": identifier},
    )
    if not centers:
        raise EntityNotFoundError(f"{label} {identifier} was not found")
    match = (
        f"MATCH (center:{spec.label} {{{spec.identifier}: $identifier}})-[r]-(neighbor) "
        "WHERE ($relationship_type IS NULL OR type(r) = $relationship_type) "
        "AND ($provenance = 'all' OR "
        "($provenance = 'real' AND r.is_synthetic = false AND neighbor.is_synthetic = false) OR "
        "($provenance = 'synthetic' AND r.is_synthetic = true)) "
    )
    parameters = {
        "identifier": identifier,
        "relationship_type": relationship_type,
        "provenance": provenance,
    }
    total = database.read_query(match + "RETURN count(r) AS total", parameters)[0]["total"]
    rows = database.read_query(
        match
        + "RETURN {id: elementId(neighbor), type: labels(neighbor)[0], "
        "properties: properties(neighbor)} AS neighbor, "
        "{id: coalesce(r.relationship_id, elementId(r)), type: type(r), "
        "start: elementId(startNode(r)), end: elementId(endNode(r)), "
        "properties: properties(r)} AS relationship "
        "ORDER BY type(r), coalesce(neighbor.name, neighbor.address, neighbor.cve_id, ''), "
        "elementId(r) SKIP $offset LIMIT $limit",
        {**parameters, "offset": offset, "limit": limit},
    )
    return {
        **centers[0],
        "neighbors": [row["neighbor"] for row in rows],
        "relationships": [row["relationship"] for row in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


def create_relationship(database: Neo4jDatabase, payload: dict[str, Any]) -> dict:
    required = {"type", "from_type", "from_id", "to_type", "to_id"}
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"Missing relationship fields: {', '.join(missing)}")
    if not all(
        isinstance(payload[key], str) and payload[key].strip() for key in required
    ):
        raise ValueError("Relationship fields must be nonempty strings")
    pattern = (payload["from_type"], payload["type"], payload["to_type"])
    if pattern not in ALLOWED_RELATIONSHIPS:
        raise ValueError(f"Unsupported relationship pattern: {pattern}")
    from_spec = entity_spec(payload["from_type"])
    to_spec = entity_spec(payload["to_type"])
    relationship_id = f"MANUAL-{uuid4()}"
    properties = {
        "relationship_id": relationship_id,
        "source": "Synthetic",
        "source_id": f"manual:{relationship_id}",
        "is_synthetic": True,
        "generator_version": "manual-crud-v1",
        "generation_seed": 0,
        "created_at": _now(),
    }
    query = (
        f"MATCH (source:{from_spec.label} {{{from_spec.identifier}: $from_id}}) "
        f"MATCH (target:{to_spec.label} {{{to_spec.identifier}: $to_id}}) "
        f"CREATE (source)-[r:{payload['type']}]->(target) "
        "SET r = $properties RETURN properties(r) AS relationship"
    )
    rows = database.write_query(
        query,
        {
            "from_id": payload["from_id"],
            "to_id": payload["to_id"],
            "properties": properties,
        },
    )
    if not rows:
        raise EntityNotFoundError("One or both relationship endpoints were not found")
    return rows[0]["relationship"]


def get_relationship(database: Neo4jDatabase, relationship_id: str) -> dict:
    rows = database.read_query(
        "MATCH (source)-[r {relationship_id: $relationship_id}]->(target) "
        "RETURN type(r) AS type, properties(r) AS properties, "
        "labels(source)[0] AS from_type, properties(source) AS from_entity, "
        "labels(target)[0] AS to_type, properties(target) AS to_entity",
        {"relationship_id": relationship_id},
    )
    if not rows:
        raise EntityNotFoundError(f"Relationship {relationship_id} was not found")
    return rows[0]


def delete_relationship(database: Neo4jDatabase, relationship_id: str) -> dict:
    existing = get_relationship(database, relationship_id)
    if not existing["properties"].get("is_synthetic"):
        raise EntityReadOnlyError("Real imported relationships are read-only")
    rows = database.write_query(
        "MATCH ()-[r {relationship_id: $relationship_id}]->() "
        "WHERE r.is_synthetic = true "
        "WITH r, properties(r) AS deleted DELETE r RETURN deleted",
        {"relationship_id": relationship_id},
    )
    if not rows:
        raise EntityNotFoundError(f"Relationship {relationship_id} was not found")
    return rows[0]["deleted"]


def supported_entity_types() -> list[str]:
    return sorted(ENTITY_SPECS)


def entity_metadata() -> dict:
    return {
        label: {"identifier": spec.identifier, "mutable": sorted(spec.mutable)}
        for label, spec in sorted(ENTITY_SPECS.items())
    }


def relationship_patterns() -> list[dict]:
    return [
        {"from_type": source, "type": kind, "to_type": target}
        for source, kind, target in sorted(ALLOWED_RELATIONSHIPS)
    ]
