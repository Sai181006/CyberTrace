from __future__ import annotations

import pytest

from backend.data.loader import node_query, relationship_query


def test_node_query_uses_merge_and_parameterized_rows() -> None:
    query = node_query("Malware")

    assert "MERGE (n:Malware {malware_id: row.id})" in query
    assert "$rows" in query
    assert "SET n += row.properties" in query


def test_relationship_query_uses_allowlisted_schema() -> None:
    query = relationship_query(("ThreatActor", "USES", "Malware"))

    assert "MATCH (source:ThreatActor {actor_id: row.from_id})" in query
    assert "MATCH (target:Malware {malware_id: row.to_id})" in query
    assert "MERGE (source)-[r:USES {relationship_id: row.id}]->(target)" in query


def test_dynamic_schema_injection_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported node label"):
        node_query("Malware) DETACH DELETE n //")
    with pytest.raises(ValueError, match="Unsupported relationship pattern"):
        relationship_query(("ThreatActor", "DELETES", "Malware"))
