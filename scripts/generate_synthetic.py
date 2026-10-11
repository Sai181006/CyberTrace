"""Generate deterministic CyberTrace demonstration records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.data.synthetic import DEFAULT_SEED, build_synthetic_dataset

DEFAULT_REAL_SUBSET = Path("data/processed/mitre-attack-subset.json")
DEFAULT_OUTPUT = Path("data/synthetic/synthetic-demo.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real-subset", type=Path, default=DEFAULT_REAL_SUBSET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with args.real_subset.open(encoding="utf-8") as source:
        real_subset = json.load(source)
    dataset = build_synthetic_dataset(real_subset, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")

    counts = dataset["metadata"]["counts"]
    print(f"Wrote {args.output}")
    print(
        "Synthetic layer: "
        f"{counts['Organization']} organizations, "
        f"{counts['Vulnerability']} vulnerabilities, "
        f"{counts['IP']} IPs, {counts['Domain']} domains, "
        f"{counts['relationships']} relationships"
    )


if __name__ == "__main__":
    main()
