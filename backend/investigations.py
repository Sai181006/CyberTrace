"""Named, parameterized Cypher investigations used by the API and demo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .db import Neo4jDatabase


@dataclass(frozen=True, slots=True)
class Investigation:
    description: str
    parameter: str | None
    cypher: str


INVESTIGATIONS = {
    "actor-malware": Investigation(
        "Malware used by a named threat actor",
        "value",
        "MATCH (a:ThreatActor)-[r:USES]->(m:Malware) WHERE a.name = $value "
        "RETURN properties(a) AS actor, properties(r) AS relationship, "
        "properties(m) AS malware LIMIT $limit",
    ),
    "malware-techniques": Investigation(
        "Techniques used by named malware",
        "value",
        "MATCH (m:Malware)-[r:USES]->(t:Technique) WHERE m.name = $value "
        "RETURN properties(m) AS malware, properties(r) AS relationship, "
        "properties(t) AS technique LIMIT $limit",
    ),
    "actor-targets": Investigation(
        "Organizations targeted by a named actor",
        "value",
        "MATCH (a:ThreatActor)-[r:TARGETS]->(o:Organization) WHERE a.name = $value "
        "RETURN properties(a) AS actor, properties(r) AS relationship, "
        "properties(o) AS organization LIMIT $limit",
    ),
    "malware-vulnerabilities": Investigation(
        "Vulnerabilities exploited by named malware",
        "value",
        "MATCH (m:Malware)-[r:EXPLOITS]->(v:Vulnerability) WHERE m.name = $value "
        "RETURN properties(m) AS malware, properties(r) AS relationship, "
        "properties(v) AS vulnerability LIMIT $limit",
    ),
    "malware-infrastructure": Investigation(
        "IP and domain infrastructure connected to named malware",
        "value",
        "MATCH (m:Malware)-[c:COMMUNICATES_WITH]->(i:IP)-[r:RESOLVES_TO]->(d:Domain) "
        "WHERE m.name = $value RETURN properties(m) AS malware, properties(c) AS communication, "
        "properties(i) AS ip, properties(r) AS resolution, properties(d) AS domain LIMIT $limit",
    ),
    "actor-investigation": Investigation(
        "Actor to malware to IP to domain multi-hop investigation",
        "value",
        "MATCH (a:ThreatActor)-[:USES]->(m:Malware)-[:COMMUNICATES_WITH]->(i:IP)"
        "-[:RESOLVES_TO]->(d:Domain) WHERE a.name = $value "
        "RETURN properties(a) AS actor, properties(m) AS malware, properties(i) AS ip, "
        "properties(d) AS domain LIMIT $limit",
    ),
    "actor-techniques": Investigation(
        "Techniques directly associated with a named actor",
        "value",
        "MATCH (a:ThreatActor)-[r:USES]->(t:Technique) WHERE a.name = $value "
        "RETURN properties(a) AS actor, properties(r) AS relationship, "
        "properties(t) AS technique LIMIT $limit",
    ),
    "actor-vulnerabilities": Investigation(
        "Synthetic vulnerabilities linked to a named actor",
        "value",
        "MATCH (a:ThreatActor)-[r:EXPLOITS]->(v:Vulnerability) WHERE a.name = $value "
        "RETURN properties(a) AS actor, properties(r) AS relationship, "
        "properties(v) AS vulnerability LIMIT $limit",
    ),
    "vulnerability-organizations": Investigation(
        "Synthetic organizations affected by a vulnerability scenario",
        "value",
        "MATCH (v:Vulnerability)-[r:AFFECTS]->(o:Organization) WHERE v.cve_id = $value "
        "RETURN properties(v) AS vulnerability, properties(r) AS relationship, "
        "properties(o) AS organization LIMIT $limit",
    ),
    "most-connected": Investigation(
        "Entities ranked by graph degree without assigning a danger score",
        None,
        "MATCH (n) OPTIONAL MATCH (n)-[r]-() RETURN labels(n)[0] AS type, "
        "properties(n) AS entity, count(r) AS degree ORDER BY degree DESC LIMIT $limit",
    ),
}


def run_investigation(
    database: Neo4jDatabase,
    name: str,
    *,
    value: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    try:
        investigation = INVESTIGATIONS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown investigation: {name}") from exc
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if investigation.parameter and not (value and value.strip()):
        raise ValueError("value is required for this investigation")
    return database.read_query(
        investigation.cypher,
        {"value": value.strip() if value else None, "limit": limit},
    )


def investigation_catalog() -> list[dict[str, str | None]]:
    return [
        {"name": name, "description": item.description, "parameter": item.parameter}
        for name, item in sorted(INVESTIGATIONS.items())
    ]
