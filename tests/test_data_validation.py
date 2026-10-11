from __future__ import annotations

import pytest

from backend.data.synthetic import build_synthetic_dataset
from backend.data.validation import validate_datasets


def _real_dataset() -> dict:
    nodes = []
    for index in range(1, 26):
        nodes.append(
            {
                "label": "ThreatActor",
                "id": f"G{index:04d}",
                "properties": _real_properties(f"G{index:04d}"),
            }
        )
    for index in range(1, 41):
        nodes.append(
            {
                "label": "Malware",
                "id": f"S{index:04d}",
                "properties": _real_properties(f"S{index:04d}"),
            }
        )
    for index in range(1, 41):
        nodes.append(
            {
                "label": "Technique",
                "id": f"T{index:04d}",
                "properties": _real_properties(f"T{index:04d}"),
            }
        )
    relationships = [
        {
            "id": "relationship--1",
            "type": "USES",
            "from": {"label": "ThreatActor", "id": "G0001"},
            "to": {"label": "Malware", "id": "S0001"},
            "properties": _real_properties("relationship--1"),
        }
    ]
    return {"nodes": nodes, "relationships": relationships}


def _real_properties(source_id: str) -> dict:
    return {
        "source": "MITRE ATT&CK",
        "source_id": source_id,
        "source_url": "https://example.test/source",
        "dataset_version": "19.2",
        "retrieved_at": "2026-09-25T11:10:15Z",
        "is_synthetic": False,
    }


def test_combined_dataset_passes_review_requirements() -> None:
    real = _real_dataset()
    synthetic = build_synthetic_dataset(real)

    report = validate_datasets(real, synthetic)

    assert report["status"] == "PASS"
    assert report["nodes"] == 159
    assert len(report["labels"]) == 7
    assert len(report["relationship_types"]) == 6
    assert report["multi_hop_investigation"] is True


def test_unmarked_synthetic_record_is_rejected() -> None:
    real = _real_dataset()
    synthetic = build_synthetic_dataset(real)
    synthetic["nodes"][0]["properties"]["is_synthetic"] = False

    with pytest.raises(ValueError, match="incorrect is_synthetic"):
        validate_datasets(real, synthetic)
