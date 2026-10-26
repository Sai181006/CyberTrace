"""HTTP routes for CyberTrace core functionality."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from itsdangerous import URLSafeTimedSerializer

from .analytics import degree_rank, pagerank, shortest_path
from .db import Neo4jDatabase
from .investigations import investigation_catalog, run_investigation
from .services import (
    EntityConflictError,
    EntityNotFoundError,
    EntityReadOnlyError,
    create_entity,
    create_relationship,
    dashboard,
    delete_entity,
    delete_relationship,
    entity_metadata,
    entity_graph,
    get_entity,
    get_relationship,
    search_entities,
    relationship_patterns,
    supported_entity_types,
    update_entity,
)

api = Blueprint("api", __name__, url_prefix="/api")


def _database() -> Neo4jDatabase:
    return current_app.extensions["neo4j"]


def _body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("A JSON object body is required")
    return body


@api.errorhandler(ValueError)
def bad_request(error: ValueError):
    return jsonify(error=str(error)), 400


@api.errorhandler(EntityNotFoundError)
def not_found(error: EntityNotFoundError):
    return jsonify(error=str(error)), 404


@api.errorhandler(EntityConflictError)
def conflict(error: EntityConflictError):
    return jsonify(error=str(error)), 409


@api.errorhandler(EntityReadOnlyError)
def read_only(error: EntityReadOnlyError):
    return jsonify(error=str(error)), 403


@api.get("/entity-types")
def entity_types_route():
    return jsonify(
        types=supported_entity_types(),
        metadata=entity_metadata(),
        relationship_patterns=relationship_patterns(),
    )


@api.get("/dashboard")
def dashboard_route():
    return jsonify(dashboard(_database()))


@api.get("/investigations")
def investigation_catalog_route():
    return jsonify(investigations=investigation_catalog())


@api.get("/investigations/<name>")
def investigation_route(name: str):
    value = request.args.get("value")
    limit = request.args.get("limit", default=50, type=int)
    results = run_investigation(_database(), name, value=value, limit=limit)
    if name == "actor-investigation":
        serializer = URLSafeTimedSerializer(current_app.secret_key, salt="cybertrace-report")
        for row in results:
            row["_save_token"] = serializer.dumps(row)
    return jsonify(results=results)


@api.get("/entities/search")
def search_route():
    term = request.args.get("q", "")
    label = request.args.get("type") or None
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(results=search_entities(_database(), term, label, limit=limit))


@api.post("/entities")
def create_entity_route():
    body = _body()
    label = body.get("type")
    properties = body.get("properties")
    if not isinstance(label, str) or not isinstance(properties, dict):
        raise ValueError("type and properties are required")
    return jsonify(entity=create_entity(_database(), label, properties)), 201


@api.get("/entities/<label>/<identifier>")
def get_entity_route(label: str, identifier: str):
    return jsonify(entity=get_entity(_database(), label, identifier))


@api.put("/entities/<label>/<identifier>")
def update_entity_route(label: str, identifier: str):
    return jsonify(entity=update_entity(_database(), label, identifier, _body()))


@api.delete("/entities/<label>/<identifier>")
def delete_entity_route(label: str, identifier: str):
    return jsonify(deleted=delete_entity(_database(), label, identifier))


@api.post("/relationships")
def create_relationship_route():
    return jsonify(relationship=create_relationship(_database(), _body())), 201


@api.get("/relationships/<relationship_id>")
def get_relationship_route(relationship_id: str):
    return jsonify(relationship=get_relationship(_database(), relationship_id))


@api.delete("/relationships/<relationship_id>")
def delete_relationship_route(relationship_id: str):
    return jsonify(deleted=delete_relationship(_database(), relationship_id))


@api.get("/graph/entity/<label>/<identifier>")
def entity_graph_route(label: str, identifier: str):
    limit = request.args.get("limit", default=12, type=int)
    offset = request.args.get("offset", default=0, type=int)
    relationship_type = request.args.get("relationship_type") or None
    provenance = request.args.get("provenance", "all")
    neighbor_type = request.args.get("neighbor_type") or None
    search = request.args.get("search", "")
    confidence_text = request.args.get("min_confidence")
    try:
        min_confidence = int(confidence_text) if confidence_text not in {None, ""} else None
    except ValueError as exc:
        raise ValueError("min_confidence must be an integer") from exc
    evidence_after = request.args.get("evidence_after") or None
    return jsonify(
        entity_graph(
            _database(), label, identifier, limit=limit, offset=offset,
            relationship_type=relationship_type, provenance=provenance,
            neighbor_type=neighbor_type, search=search,
            min_confidence=min_confidence, evidence_after=evidence_after,
        )
    )


@api.get("/analytics/path")
def shortest_path_route():
    required = ("from_type", "from_id", "to_type", "to_id")
    parameters = {name: request.args.get(name, "").strip() for name in required}
    if not all(parameters.values()):
        raise ValueError("from_type, from_id, to_type, and to_id are required")
    max_hops = request.args.get("max_hops", default=6, type=int)
    return jsonify(shortest_path(_database(), **parameters, max_hops=max_hops))


@api.get("/analytics/pagerank")
def pagerank_route():
    scope = request.args.get("scope", "real")
    limit = request.args.get("limit", default=10, type=int)
    return jsonify(pagerank(_database(), scope=scope, limit=limit))


@api.get("/analytics/degree")
def degree_rank_route():
    scope = request.args.get("scope", "real")
    limit = request.args.get("limit", default=10, type=int)
    return jsonify(degree_rank(_database(), scope=scope, limit=limit))
