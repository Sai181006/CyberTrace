"""Execute all ten named Cypher investigations against live Neo4j."""

from __future__ import annotations

from backend.config import Settings
from backend.db import Neo4jDatabase
from backend.investigations import INVESTIGATIONS, run_investigation


def _value(database: Neo4jDatabase, query: str, key: str) -> str:
    return str(database.read_query(query)[0][key])


def main() -> None:
    database = Neo4jDatabase(Settings.from_env())
    try:
        actor = _value(
            database,
            "MATCH (a:ThreatActor)-[:USES]->(:Malware) RETURN a.name AS value LIMIT 1",
            "value",
        )
        malware = _value(
            database,
            "MATCH (m:Malware)-[:USES]->(:Technique) RETURN m.name AS value LIMIT 1",
            "value",
        )
        target_actor = _value(
            database,
            "MATCH (a:ThreatActor)-[:TARGETS]->() RETURN a.name AS value LIMIT 1",
            "value",
        )
        vulnerable_malware = _value(
            database,
            "MATCH (m:Malware)-[:EXPLOITS]->() RETURN m.name AS value LIMIT 1",
            "value",
        )
        infrastructure_malware = _value(
            database,
            "MATCH (m:Malware)-[:COMMUNICATES_WITH]->() RETURN m.name AS value LIMIT 1",
            "value",
        )
        technique_actor = _value(
            database,
            "MATCH (a:ThreatActor)-[:USES]->(:Technique) RETURN a.name AS value LIMIT 1",
            "value",
        )
        exploit_actor = _value(
            database,
            "MATCH (a:ThreatActor)-[:EXPLOITS]->() RETURN a.name AS value LIMIT 1",
            "value",
        )
        vulnerability = _value(
            database,
            "MATCH (v:Vulnerability)-[:AFFECTS]->() RETURN v.cve_id AS value LIMIT 1",
            "value",
        )
        values = {
            "actor-malware": actor,
            "malware-techniques": malware,
            "actor-targets": target_actor,
            "malware-vulnerabilities": vulnerable_malware,
            "malware-infrastructure": infrastructure_malware,
            "actor-investigation": target_actor,
            "actor-techniques": technique_actor,
            "actor-vulnerabilities": exploit_actor,
            "vulnerability-organizations": vulnerability,
            "most-connected": None,
        }
        for name in INVESTIGATIONS:
            rows = run_investigation(database, name, value=values[name], limit=10)
            print(f"PASS  {name:30} rows={len(rows)}")
    finally:
        database.close()
    print("TEN CYPHER INVESTIGATIONS READY")


if __name__ == "__main__":
    main()
