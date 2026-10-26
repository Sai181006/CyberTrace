"""Exercise both Review 3 graph analytics against live Neo4j."""

from __future__ import annotations

from math import isfinite

from backend.analytics import degree_rank, pagerank, shortest_path
from backend.config import Settings
from backend.db import Neo4jDatabase
from backend.services import EntityNotFoundError, entity_graph


def main() -> None:
    database = Neo4jDatabase(Settings.from_env())
    try:
        pairs = database.read_query(
            "MATCH (a:ThreatActor)-[:USES]->(m:Malware) "
            "MATCH (m)-[:COMMUNICATES_WITH]->(i:IP) "
            "MATCH (i)-[:RESOLVES_TO]->(d:Domain) "
            "RETURN a.actor_id AS actor_id, d.domain_id AS domain_id LIMIT 1"
        )
        if not pairs:
            raise AssertionError("No actor to domain path exists")
        pair = pairs[0]
        neighborhood = entity_graph(database, "ThreatActor", pair["actor_id"], limit=12)
        if neighborhood["total"] < len(neighborhood["neighbors"]):
            raise AssertionError("Graph page exceeds its total")
        uses = entity_graph(
            database, "ThreatActor", pair["actor_id"],
            limit=12, relationship_type="USES", provenance="real",
        )
        if not uses["neighbors"] or any(
            item["type"] != "USES" or item["properties"]["is_synthetic"]
            for item in uses["relationships"]
        ):
            raise AssertionError("Real USES graph filter returned incorrect links")
        print(f"PASS  Paged graph exploration: {neighborhood['total']} links, real USES filter")
        path = shortest_path(
            database, "ThreatActor", pair["actor_id"], "Domain", pair["domain_id"]
        )
        if not path["found"] or not 1 <= path["hops"] <= 6:
            raise AssertionError("Shortest path did not return a bounded path")
        if len(path["nodes"]) != path["hops"] + 1:
            raise AssertionError("Path nodes and relationships disagree")
        print(f"PASS  Shortest path: {path['hops']} relationships")

        no_path = shortest_path(
            database,
            "ThreatActor",
            pair["actor_id"],
            "Domain",
            pair["domain_id"],
            max_hops=1,
        )
        if no_path["found"]:
            raise AssertionError(
                "One-hop query unexpectedly found an actor to domain path"
            )
        print("PASS  Hop limit returns a clear no-path result")

        try:
            shortest_path(
                database, "ThreatActor", "DOES-NOT-EXIST", "Domain", pair["domain_id"]
            )
        except EntityNotFoundError:
            print("PASS  Missing endpoint is distinct from no path")
        else:
            raise AssertionError("Missing endpoint was not reported")

        for scope in ("real", "all"):
            ranking = pagerank(database, scope=scope)
            if not ranking["results"] or not ranking["converged"]:
                raise AssertionError(f"PageRank {scope} returned no converged results")
            if not all(
                isfinite(row["score"]) and row["score"] > 0
                for row in ranking["results"]
            ):
                raise AssertionError(f"PageRank {scope} returned an invalid score")
            if scope == "real" and any(
                row["entity"]["is_synthetic"] for row in ranking["results"]
            ):
                raise AssertionError("Real-only ranking contains a synthetic entity")
            print(
                f"PASS  PageRank {scope}: {ranking['node_count']} nodes, "
                f"{ranking['relationship_count']} relationships, "
                f"{ranking['iterations']} iterations"
            )
            degree = degree_rank(database, scope=scope)
            if not degree["results"] or degree["node_count"] != ranking["node_count"]:
                raise AssertionError(f"Degree {scope} scope differs from PageRank")
            if scope == "real" and any(
                row["entity"]["is_synthetic"] for row in degree["results"]
            ):
                raise AssertionError("Real-only degree ranking contains synthetic data")
            print(f"PASS  Degree {scope}: top count {degree['results'][0]['degree']}")
    finally:
        database.close()
    print("CYBERTRACE ANALYTICS READY")


if __name__ == "__main__":
    main()
