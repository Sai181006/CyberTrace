"""Verify the live Neo4j database after loading CyberTrace data."""

from __future__ import annotations

from backend.config import Settings
from backend.db import Neo4jDatabase


def main() -> None:
    database = Neo4jDatabase(Settings.from_env())
    try:
        database.verify_connectivity()
        totals = database.read_query(
            "MATCH (n) WITH count(n) AS nodes "
            "MATCH ()-[r]->() RETURN nodes, count(r) AS relationships"
        )[0]
        labels = database.read_query(
            "MATCH (n) UNWIND labels(n) AS label "
            "RETURN label, count(*) AS count ORDER BY label"
        )
        relationship_types = database.read_query(
            "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS count ORDER BY type"
        )
        provenance = database.read_query(
            "MATCH (n) RETURN n.is_synthetic AS is_synthetic, count(*) AS count "
            "ORDER BY is_synthetic"
        )
        constraints = database.read_query(
            "SHOW CONSTRAINTS YIELD name RETURN name ORDER BY name"
        )
        indexes = database.read_query(
            "SHOW INDEXES YIELD name, type, owningConstraint "
            "WHERE type <> 'LOOKUP' AND owningConstraint IS NULL "
            "RETURN name ORDER BY name"
        )
        paths = database.read_query(
            "MATCH p=(a:ThreatActor)-[:USES]->(m:Malware)"
            "-[:COMMUNICATES_WITH]->(i:IP)-[:RESOLVES_TO]->(d:Domain) "
            "RETURN count(p) AS count"
        )[0]["count"]
    finally:
        database.close()

    checks = {
        "Node count >= 100": totals["nodes"] >= 100,
        "Relationship count > 0": totals["relationships"] > 0,
        "Seven node labels": len(labels) == 7,
        "Six relationship types": len(relationship_types) == 6,
        "Real and synthetic nodes": len(provenance) == 2,
        "Seven uniqueness constraints": len(constraints) == 7,
        "Six explicit search indexes": len(indexes) == 6,
        "Multi-hop path exists": paths > 0,
    }

    print("CyberTrace Live Database Verification")
    print(f"Nodes:          {totals['nodes']}")
    print(f"Relationships:  {totals['relationships']}")
    print(f"Labels:         {', '.join(row['label'] for row in labels)}")
    print(f"Types:          {', '.join(row['type'] for row in relationship_types)}")
    print(f"Constraints:    {len(constraints)}")
    print(f"Search indexes: {len(indexes)} (+ 7 constraint-backed indexes)")
    print(f"Multi-hop paths:{paths:>5}")
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL':4}  {name}")
    if not all(checks.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
