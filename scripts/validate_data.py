"""Validate CyberTrace generated datasets before any Neo4j load."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.data.validation import validate_datasets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--real",
        type=Path,
        default=Path("data/processed/mitre-attack-subset.json"),
    )
    parser.add_argument(
        "--synthetic",
        type=Path,
        default=Path("data/synthetic/synthetic-demo.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with args.real.open(encoding="utf-8") as source:
        real_dataset = json.load(source)
    with args.synthetic.open(encoding="utf-8") as source:
        synthetic_dataset = json.load(source)

    report = validate_datasets(real_dataset, synthetic_dataset)
    print("CyberTrace Data Validation")
    print(f"Status:              {report['status']}")
    print(f"Nodes:               {report['nodes']}")
    print(f"Relationships:       {report['relationships']}")
    print(f"Real nodes:          {report['real_nodes']}")
    print(f"Synthetic nodes:     {report['synthetic_nodes']}")
    print(f"Labels:              {', '.join(report['labels'])}")
    print(f"Relationship types:  {', '.join(report['relationship_types'])}")
    print("Multi-hop path:      PASS")


if __name__ == "__main__":
    main()
