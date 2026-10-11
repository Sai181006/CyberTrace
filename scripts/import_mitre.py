"""Create a deterministic CyberTrace subset from pinned MITRE ATT&CK STIX."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from backend.data.mitre import build_subset, load_stix_bundle

DEFAULT_INPUT = Path("data/raw/enterprise-attack-19.2.json")
DEFAULT_MANIFEST = Path("data/source-manifest.json")
DEFAULT_OUTPUT = Path("data/processed/mitre-attack-subset.json")


def _load_source(manifest_path: Path) -> dict[str, Any]:
    with manifest_path.open(encoding="utf-8") as source:
        manifest = json.load(source)
    try:
        return manifest["sources"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("Source manifest does not contain a source entry") from exc


def _verify_checksum(path: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch for {path}: expected {expected_sha256}, got {actual}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--groups", type=int, default=25)
    parser.add_argument("--software", type=int, default=40)
    parser.add_argument("--techniques", type=int, default=40)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    dataset = _load_source(args.manifest)
    _verify_checksum(args.input, dataset["sha256"])
    bundle = load_stix_bundle(args.input)
    subset = build_subset(
        bundle,
        dataset,
        group_limit=args.groups,
        software_limit=args.software,
        technique_limit=args.techniques,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(subset, indent=2) + "\n", encoding="utf-8")

    counts = subset["metadata"]["counts"]
    print(f"Wrote {args.output}")
    print(
        "Real subset: "
        f"{counts.get('ThreatActor', 0)} actors, "
        f"{counts.get('Malware', 0)} software, "
        f"{counts.get('Technique', 0)} techniques, "
        f"{counts['relationships']} documented USES relationships"
    )


if __name__ == "__main__":
    main()
