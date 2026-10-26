from __future__ import annotations

from math import isclose, isfinite

import pytest

from backend.analytics import calculate_pagerank, degree_rank, pagerank, shortest_path
from backend.services import EntityNotFoundError


class AnalyticsDatabase:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    def read_query(self, query: str, parameters: dict | None = None) -> list[dict]:
        self.calls.append((query, parameters))
        if "RETURN properties(n) AS entity" in query:
            if parameters == {"identifier": "missing"}:
                return []
            return [{"entity": {"name": "Example"}}]
        if "shortestPath" in query:
            return [{"nodes": [], "relationships": []}]
        if "RETURN elementId(n) AS id" in query:
            return [
                {
                    "id": "a",
                    "type": "ThreatActor",
                    "properties": {"name": "A", "is_synthetic": False},
                },
                {
                    "id": "b",
                    "type": "Technique",
                    "properties": {"name": "B", "is_synthetic": False},
                },
            ]
        if "RETURN elementId(a) AS start" in query:
            return [{"start": "a", "end": "b"}]
        return []


def test_shortest_path_validates_and_parameters() -> None:
    database = AnalyticsDatabase()
    result = shortest_path(
        database, "ThreatActor", "G0007", "Domain", "SYN-DOM-01", max_hops=3
    )
    assert result == {"found": False, "hops": None, "nodes": [], "relationships": []}
    query, parameters = database.calls[-1]
    assert "shortestPath" in query and "[*..3]" in query
    assert "$from_id" in query and "$to_id" in query
    assert parameters == {"from_id": "G0007", "to_id": "SYN-DOM-01"}


def test_shortest_path_missing_endpoint_and_hop_limit() -> None:
    database = AnalyticsDatabase()
    with pytest.raises(EntityNotFoundError):
        shortest_path(database, "ThreatActor", "missing", "Domain", "SYN-DOM-01")
    with pytest.raises(ValueError, match="max_hops"):
        shortest_path(
            database, "ThreatActor", "G0007", "Domain", "SYN-DOM-01", max_hops=7
        )


def test_pagerank_converges_and_preserves_probability_mass() -> None:
    scores, iterations, converged = calculate_pagerank(
        ["a", "b", "c"], [("a", "b"), ("b", "c"), ("c", "a")]
    )
    assert converged and iterations <= 100
    assert isclose(sum(scores.values()), 1.0, abs_tol=1e-10)
    assert all(isclose(score, 1 / 3, abs_tol=1e-10) for score in scores.values())


def test_pagerank_handles_dangling_nodes_and_real_scope() -> None:
    database = AnalyticsDatabase()
    result = pagerank(database, scope="real")
    assert result["node_count"] == 2
    assert result["relationship_count"] == 1
    assert result["results"][0]["entity"]["name"] == "B"
    assert all(isfinite(row["score"]) for row in result["results"])
    assert "is_synthetic = false" in database.calls[-1][0]
    with pytest.raises(ValueError, match="scope"):
        pagerank(database, scope="unsupported")


def test_pagerank_ties_use_stable_entity_ids() -> None:
    class TiedDatabase:
        def read_query(self, query: str, parameters: dict | None = None) -> list[dict]:
            if "RETURN elementId(n) AS id" in query:
                return [
                    {
                        "id": "a-internal",
                        "type": "Technique",
                        "properties": {"technique_id": "T2000"},
                    },
                    {
                        "id": "z-internal",
                        "type": "Technique",
                        "properties": {"technique_id": "T1000"},
                    },
                ]
            return []

    ranked = pagerank(TiedDatabase(), scope="all")
    assert [row["entity"]["technique_id"] for row in ranked["results"]] == [
        "T1000",
        "T2000",
    ]


def test_degree_rank_counts_both_endpoints_and_respects_scope() -> None:
    database = AnalyticsDatabase()
    result = degree_rank(database, scope="real")
    assert result["node_count"] == 2
    assert result["relationship_count"] == 1
    assert [row["degree"] for row in result["results"]] == [1, 1]
    assert "is_synthetic = false" in database.calls[-1][0]
    with pytest.raises(ValueError, match="limit"):
        degree_rank(database, limit=0)
