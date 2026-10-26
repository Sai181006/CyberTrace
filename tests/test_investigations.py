from __future__ import annotations

import pytest

from backend.investigations import INVESTIGATIONS, run_investigation


class RecordingDatabase:
    def __init__(self) -> None:
        self.query = ""
        self.parameters = {}

    def read_query(self, query: str, parameters: dict) -> list[dict]:
        self.query = query
        self.parameters = parameters
        return []


def test_ten_named_investigations_exist() -> None:
    assert len(INVESTIGATIONS) == 10
    assert "actor-investigation" in INVESTIGATIONS
    assert "most-connected" in INVESTIGATIONS


def test_actor_investigation_exposes_every_relationship() -> None:
    query = INVESTIGATIONS["actor-investigation"].cypher

    assert "properties(uses) AS uses" in query
    assert "properties(communication) AS communication" in query
    assert "properties(resolution) AS resolution" in query


def test_investigation_parameters_are_not_interpolated() -> None:
    database = RecordingDatabase()
    malicious = "x' MATCH (n) DETACH DELETE n //"

    run_investigation(database, "actor-malware", value=malicious)

    assert malicious not in database.query
    assert database.parameters["value"] == malicious
    assert "$value" in database.query


def test_unknown_investigation_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown investigation"):
        run_investigation(RecordingDatabase(), "delete-everything", value="x")
