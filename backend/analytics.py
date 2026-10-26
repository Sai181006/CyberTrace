"""Bounded path finding and PageRank for the CyberTrace graph."""

from __future__ import annotations

from collections import defaultdict
from math import isfinite
from typing import Any

from .db import Neo4jDatabase
from .entities import ENTITY_SPECS, entity_spec
from .services import get_entity


def shortest_path(
    database: Neo4jDatabase,
    from_type: str,
    from_id: str,
    to_type: str,
    to_id: str,
    *,
    max_hops: int = 6,
) -> dict[str, Any]:
    """Find a bounded undirected path while preserving edge direction and provenance."""
    if not isinstance(max_hops, int) or not 1 <= max_hops <= 6:
        raise ValueError("max_hops must be between 1 and 6")
    source = entity_spec(from_type)
    target = entity_spec(to_type)
    if not from_id.strip() or not to_id.strip():
        raise ValueError("Both entity IDs are required")
    if from_type == to_type and from_id == to_id:
        raise ValueError("Choose two different entities")

    # Keep missing endpoints distinct from an existing pair with no path.
    get_entity(database, source.label, from_id)
    get_entity(database, target.label, to_id)
    query = (
        f"MATCH (source:{source.label} {{{source.identifier}: $from_id}}) "
        f"MATCH (target:{target.label} {{{target.identifier}: $to_id}}) "
        f"OPTIONAL MATCH path = shortestPath((source)-[*..{max_hops}]-(target)) "
        "RETURN CASE WHEN path IS NULL THEN [] ELSE "
        "[n IN nodes(path) | {id: elementId(n), type: labels(n)[0], "
        "properties: properties(n)}] END AS nodes, "
        "CASE WHEN path IS NULL THEN [] ELSE "
        "[r IN relationships(path) | {id: coalesce(r.relationship_id, elementId(r)), "
        "type: type(r), start: elementId(startNode(r)), end: elementId(endNode(r)), "
        "properties: properties(r)}] END AS relationships"
    )
    rows = database.read_query(query, {"from_id": from_id, "to_id": to_id})
    if not rows:
        return {"found": False, "hops": None, "nodes": [], "relationships": []}
    row = rows[0]
    nodes = row["nodes"]
    relationships = row["relationships"]
    return {
        "found": bool(nodes),
        "hops": len(relationships) if nodes else None,
        "nodes": nodes,
        "relationships": relationships,
    }


def calculate_pagerank(
    node_ids: list[str],
    edges: list[tuple[str, str]],
    *,
    damping: float = 0.85,
    max_iterations: int = 100,
    tolerance: float = 1e-10,
) -> tuple[dict[str, float], int, bool]:
    """Calculate directed PageRank, counting each stored relationship as an edge."""
    if not node_ids:
        return {}, 0, True
    if not 0 < damping < 1 or max_iterations < 1 or tolerance <= 0:
        raise ValueError("Invalid PageRank settings")
    node_set = set(node_ids)
    if len(node_set) != len(node_ids):
        raise ValueError("PageRank node IDs must be unique")
    outgoing: dict[str, list[str]] = defaultdict(list)
    for start, end in edges:
        if start in node_set and end in node_set:
            outgoing[start].append(end)
    count = len(node_ids)
    ranks = {node_id: 1.0 / count for node_id in node_ids}
    for iteration in range(1, max_iterations + 1):
        dangling = sum(ranks[node_id] for node_id in node_ids if not outgoing[node_id])
        baseline = (1.0 - damping) / count + damping * dangling / count
        updated = {node_id: baseline for node_id in node_ids}
        for start in node_ids:
            targets = outgoing[start]
            if targets:
                contribution = damping * ranks[start] / len(targets)
                for end in targets:
                    updated[end] += contribution
        delta = sum(abs(updated[node_id] - ranks[node_id]) for node_id in node_ids)
        ranks = updated
        if delta < tolerance:
            return ranks, iteration, True
    return ranks, max_iterations, False


def _graph_snapshot(database: Neo4jDatabase, scope: str, limit: int) -> tuple[list[dict], list[dict]]:
    if scope not in {"real", "all"}:
        raise ValueError("scope must be real or all")
    if not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    where_nodes = "WHERE n.is_synthetic = false " if scope == "real" else ""
    where_edges = (
        "WHERE a.is_synthetic = false AND b.is_synthetic = false "
        "AND r.is_synthetic = false "
        if scope == "real"
        else ""
    )
    nodes = database.read_query(
        f"MATCH (n) {where_nodes}RETURN elementId(n) AS id, "
        "labels(n)[0] AS type, properties(n) AS properties"
    )
    edges = database.read_query(
        f"MATCH (a)-[r]->(b) {where_edges}"
        "RETURN elementId(a) AS start, elementId(b) AS end"
    )
    return nodes, edges


def _rank_key(row: dict, score: float) -> tuple:
    entity_type = row["type"]
    return (
        -score,
        entity_type,
        str(row["properties"].get(ENTITY_SPECS[entity_type].identifier, ""))
        if entity_type in ENTITY_SPECS else row["id"],
    )


def pagerank(
    database: Neo4jDatabase, *, scope: str = "real", limit: int = 10
) -> dict[str, Any]:
    nodes, edges = _graph_snapshot(database, scope, limit)
    scores, iterations, converged = calculate_pagerank(
        [row["id"] for row in nodes],
        [(row["start"], row["end"]) for row in edges],
    )
    ranked = sorted(nodes, key=lambda row: _rank_key(row, scores[row["id"]]))
    results = [
        {"type": row["type"], "entity": row["properties"], "score": scores[row["id"]]}
        for row in ranked[:limit]
    ]
    if not all(isfinite(result["score"]) for result in results):
        raise ValueError("PageRank produced a non-finite score")
    return {
        "scope": scope,
        "node_count": len(nodes),
        "relationship_count": len(edges),
        "iterations": iterations,
        "converged": converged,
        "results": results,
    }


def degree_rank(
    database: Neo4jDatabase, *, scope: str = "real", limit: int = 10
) -> dict[str, Any]:
    """Rank nodes by incident relationship count in the selected graph snapshot."""
    nodes, edges = _graph_snapshot(database, scope, limit)
    degrees = {row["id"]: 0 for row in nodes}
    for edge in edges:
        if edge["start"] in degrees and edge["end"] in degrees:
            degrees[edge["start"]] += 1
            degrees[edge["end"]] += 1
    ranked = sorted(nodes, key=lambda row: _rank_key(row, degrees[row["id"]]))
    return {
        "scope": scope,
        "node_count": len(nodes),
        "relationship_count": len(edges),
        "results": [
            {"type": row["type"], "entity": row["properties"], "degree": degrees[row["id"]]}
            for row in ranked[:limit]
        ],
    }
