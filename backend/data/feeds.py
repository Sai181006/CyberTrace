"""Official, bounded threat-intelligence feed adapters."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from backend.data.mitre import build_subset
from backend.data.loader import load_datasets
from backend.db import Neo4jDatabase
from backend.schema import all_schema_statements
from backend.store import AppStore

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCES = {"mitre-attack": ATTACK_URL, "cisa-kev": KEV_URL}
MAX_SOURCE_BYTES = {"mitre-attack": 90_000_000, "cisa-kev": 10_000_000}
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,19}$")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def fetch_source(source: str) -> bytes:
    if source not in SOURCES:
        raise ValueError("Unknown threat-intelligence source")
    url = SOURCES[source]
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "CyberTrace/0.2 (+local research app)"})
    with urlopen(request, timeout=45) as response:
        final_url = response.geturl()
        host = urlparse(final_url).hostname or ""
        if urlparse(final_url).scheme != "https" or not (
            host == "raw.githubusercontent.com" if source == "mitre-attack"
            else host == "cisa.gov" or host.endswith(".cisa.gov")
        ):
            raise ValueError("Feed redirected outside its approved HTTPS host")
        data = response.read(MAX_SOURCE_BYTES[source] + 1)
    if len(data) > MAX_SOURCE_BYTES[source]:
        raise ValueError("Feed exceeds its configured size limit")
    return data


def build_kev_dataset(catalog: dict, *, retrieved_at: str) -> dict:
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("Expected a CISA KEV catalog with vulnerabilities")
    version = catalog.get("catalogVersion")
    if not isinstance(version, str) or not version:
        raise ValueError("CISA KEV catalogVersion is required")
    entries = catalog["vulnerabilities"]
    if catalog.get("count") != len(entries):
        raise ValueError("CISA KEV catalog count does not match its entries")
    nodes = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid CISA KEV vulnerability")
        cve = entry.get("cveID")
        if not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve) or cve in seen:
            raise ValueError("Invalid or duplicate CISA KEV CVE ID")
        seen.add(cve)
        nodes.append({
            "label": "Vulnerability",
            "id": cve,
            "properties": {
                "cve_id": cve,
                "name": str(entry.get("vulnerabilityName") or cve),
                "description": str(entry.get("shortDescription") or ""),
                "vendor_project": str(entry.get("vendorProject") or ""),
                "product": str(entry.get("product") or ""),
                "date_added": str(entry.get("dateAdded") or ""),
                "due_date": str(entry.get("dueDate") or ""),
                "required_action": str(entry.get("requiredAction") or ""),
                "known_ransomware_campaign_use": str(entry.get("knownRansomwareCampaignUse") or "Unknown"),
                "source": "CISA KEV",
                "source_id": cve,
                "source_url": KEV_URL,
                "dataset_version": version,
                "retrieved_at": retrieved_at,
                "is_synthetic": False,
            },
        })
    return {"metadata": {"source": "CISA KEV", "dataset_version": version, "retrieved_at": retrieved_at}, "nodes": nodes, "relationships": []}


def build_attack_dataset(bundle: dict, *, retrieved_at: str) -> dict:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle")
    collections = [item for item in bundle["objects"] if item.get("type") == "x-mitre-collection" and item.get("name") == "Enterprise ATT&CK"]
    if len(collections) != 1 or not isinstance(collections[0].get("x_mitre_version"), str):
        raise ValueError("Enterprise ATT&CK collection version is missing")
    return build_subset(bundle, {
        "release": collections[0]["x_mitre_version"],
        "retrieved_at": retrieved_at,
        "download_url": ATTACK_URL,
    })


def _reject_synthetic_collisions(database: Neo4jDatabase, dataset: dict) -> None:
    for label in {node["label"] for node in dataset["nodes"]}:
        identifier = {"ThreatActor": "actor_id", "Malware": "malware_id", "Technique": "technique_id", "Vulnerability": "cve_id"}[label]
        ids = [node["id"] for node in dataset["nodes"] if node["label"] == label]
        rows = database.read_query(
            f"MATCH (n:{label}) WHERE n.{identifier} IN $ids AND n.is_synthetic = true "
            f"RETURN n.{identifier} AS id LIMIT 1", {"ids": ids}
        )
        if rows:
            raise ValueError(f"Feed conflicts with synthetic {label} {rows[0]['id']}")


def sync_source(database: Neo4jDatabase, store: AppStore, source: str, *, fetcher=fetch_source, force: bool = False) -> dict:
    if source not in SOURCES:
        raise ValueError("Unknown threat-intelligence source")
    version = ""
    digest = ""
    try:
        raw = fetcher(source)
        digest = hashlib.sha256(raw).hexdigest()
        if not force and store.latest_source_hash(source) == digest:
            return store.record_source_run(source, store.latest_source_version(source) or "unknown", digest, "unchanged", 0, 0)
        payload = json.loads(raw)
        retrieved_at = _utc_now()
        dataset = (build_attack_dataset(payload, retrieved_at=retrieved_at)
                   if source == "mitre-attack" else build_kev_dataset(payload, retrieved_at=retrieved_at))
        version = dataset["metadata"]["dataset_version"]
        cache = store.path.parent / "source-cache" / source
        cache.mkdir(parents=True, exist_ok=True)
        archive = cache / f"{digest}.json"
        if not archive.exists():
            archive.write_bytes(raw)
        for statement in all_schema_statements():
            database.run_schema_statement(statement)
        _reject_synthetic_collisions(database, dataset)
        result = load_datasets(database, [dataset])
        store.record_claims(dataset, digest)
        return store.record_source_run(
            source, version, digest, "imported", result["nodes_processed"], result["relationships_processed"], str(archive)
        )
    except Exception as exc:
        store.record_source_run(source, version, digest, "failed", 0, 0, str(exc))
        raise
