from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.data.feeds import build_attack_dataset, build_kev_dataset, sync_source
from backend.store import AppStore


def _kev() -> dict:
    return {
        "catalogVersion": "2026.10.27", "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2026-12345", "vulnerabilityName": "Example flaw",
            "shortDescription": "Example description", "vendorProject": "Example vendor",
            "product": "Example product", "dateAdded": "2026-10-27", "dueDate": "2026-11-17",
            "requiredAction": "Apply vendor update", "knownRansomwareCampaignUse": "Unknown",
        }],
    }


def test_cisa_adapter_preserves_claim_provenance_without_inventing_links() -> None:
    dataset = build_kev_dataset(_kev(), retrieved_at="2026-10-27T00:00:00Z")
    assert dataset["relationships"] == []
    assert dataset["nodes"][0]["properties"]["source"] == "CISA KEV"
    assert dataset["nodes"][0]["properties"]["dataset_version"] == "2026.10.27"
    assert dataset["nodes"][0]["properties"]["is_synthetic"] is False
    invalid = _kev()
    invalid["count"] = 2
    with pytest.raises(ValueError, match="count"):
        build_kev_dataset(invalid, retrieved_at="2026-10-27T00:00:00Z")


def test_attack_adapter_requires_a_versioned_enterprise_collection() -> None:
    with pytest.raises(ValueError, match="collection version"):
        build_attack_dataset({"type": "bundle", "objects": []}, retrieved_at="now")


class FakeDatabase:
    def __init__(self) -> None:
        self.statements = []

    def run_schema_statement(self, statement: str) -> None:
        self.statements.append(statement)

    def read_query(self, query: str, parameters: dict) -> list:
        return []


def test_sync_archives_and_skips_unchanged_feed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = AppStore(tmp_path / "app.sqlite3")
    database = FakeDatabase()
    calls = []

    def fake_load(db, datasets):
        calls.append(datasets[0])
        return {"nodes_processed": 1, "relationships_processed": 0}

    monkeypatch.setattr("backend.data.feeds.load_datasets", fake_load)
    raw = json.dumps(_kev()).encode()
    first = sync_source(database, store, "cisa-kev", fetcher=lambda source: raw)
    second = sync_source(database, store, "cisa-kev", fetcher=lambda source: raw)
    assert first["status"] == "imported"
    assert second["status"] == "unchanged"
    assert len(calls) == 1
    assert (tmp_path / "source-cache" / "cisa-kev" / f"{first['sha256']}.json").read_bytes() == raw
    assert store.source_runs()[0]["status"] == "unchanged"
    claims = store.claims_for("node", "Vulnerability", "CVE-2026-12345")
    assert claims[0]["version"] == "2026.10.27"
    assert claims[0]["sha256"] == first["sha256"]


def test_source_claim_history_keeps_multiple_versions(tmp_path: Path) -> None:
    store = AppStore(tmp_path / "app.sqlite3")
    first = build_kev_dataset(_kev(), retrieved_at="2026-10-27T00:00:00Z")
    second = build_kev_dataset({**_kev(), "catalogVersion": "2026.10.28"}, retrieved_at="2026-10-28T00:00:00Z")
    store.record_claims(first, "hash-one")
    store.record_claims(second, "hash-two")
    claims = store.claims_for("node", "Vulnerability", "CVE-2026-12345")
    assert [row["version"] for row in claims] == ["2026.10.28", "2026.10.27"]
