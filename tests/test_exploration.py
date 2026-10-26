from __future__ import annotations

import pytest

from backend.services import entity_graph


class GraphDatabase:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def read_query(self, query: str, parameters: dict) -> list[dict]:
        self.calls.append((query, parameters))
        if "AS center_id" in query:
            return [{"center_id": "center", "center": {"name": "APT28"}, "center_type": "ThreatActor"}]
        if "count(r) AS total" in query:
            return [{"total": 25}]
        return [{
            "neighbor": {"id": "neighbor", "type": "Malware", "properties": {"name": "Example"}},
            "relationship": {"id": "relation", "type": "USES", "start": "center", "end": "neighbor", "properties": {"is_synthetic": False}},
        }]


def test_graph_pages_and_filters_keep_query_values_parameterized() -> None:
    database = GraphDatabase()
    result = entity_graph(
        database, "ThreatActor", "G0007", limit=12, offset=12,
        relationship_type="USES", provenance="real",
    )
    assert result["total"] == 25
    assert result["offset"] == 12
    assert result["neighbors"][0]["type"] == "Malware"
    query, parameters = database.calls[-1]
    assert "SKIP $offset LIMIT $limit" in query
    assert parameters["relationship_type"] == "USES"
    assert parameters["provenance"] == "real"


def test_graph_rejects_unsupported_filters() -> None:
    database = GraphDatabase()
    with pytest.raises(ValueError, match="relationship type"):
        entity_graph(database, "ThreatActor", "G0007", relationship_type="DELETES")
    with pytest.raises(ValueError, match="provenance"):
        entity_graph(database, "ThreatActor", "G0007", provenance="untrusted")
    with pytest.raises(ValueError, match="offset"):
        entity_graph(database, "ThreatActor", "G0007", offset=-1)
