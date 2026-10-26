from __future__ import annotations

import pytest

from backend.services import create_relationship


class RecordingDatabase:
    def write_query(self, query: str, parameters: dict) -> list:
        return [{"relationship": parameters["properties"]}]


def _payload() -> dict:
    return {"type": "USES", "from_type": "ThreatActor", "from_id": "G0007", "to_type": "Malware", "to_id": "S0002"}


def test_manual_link_retains_bounded_temporal_and_confidence_evidence() -> None:
    result = create_relationship(RecordingDatabase(), {
        **_payload(), "first_seen": "2026-10-01T00:00:00Z", "last_seen": "2026-10-02T00:00:00Z",
        "confidence": 70, "confidence_basis": "Analyst training example", "evidence_url": "https://example.com/evidence",
    })
    assert result["confidence"] == 70
    assert result["first_seen"] == "2026-10-01T00:00:00Z"
    assert result["is_synthetic"] is True


@pytest.mark.parametrize("extra", [
    {"confidence": 101}, {"confidence": True}, {"first_seen": "yesterday"},
    {"evidence_url": "http://insecure.example"}, {"unexpected": "value"},
    {"first_seen": "2026-10-02T00:00:00Z", "last_seen": "2026-10-01T00:00:00Z"},
])
def test_manual_link_rejects_invalid_evidence(extra: dict) -> None:
    with pytest.raises(ValueError):
        create_relationship(RecordingDatabase(), {**_payload(), **extra})
