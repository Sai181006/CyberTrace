"""Validate and idempotently load CyberTrace datasets into Neo4j."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from backend.config import Settings
from backend.data.loader import load_datasets
from backend.data.validation import validate_datasets
from backend.db import Neo4jDatabase
from backend.schema import all_schema_statements
from backend.store import AppStore


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

    validation = validate_datasets(real_dataset, synthetic_dataset)
    print(
        f"Validated {validation['nodes']} nodes and "
        f"{validation['relationships']} relationships."
    )

    database = Neo4jDatabase(Settings.from_env())
    try:
        database.verify_connectivity()
        for statement in all_schema_statements():
            database.run_schema_statement(statement)
        report = load_datasets(database, [real_dataset, synthetic_dataset])
    finally:
        database.close()

    print(f"Nodes processed:         {report['nodes_processed']}")
    print(f"Relationships processed: {report['relationships_processed']}")
    store = AppStore(Settings.from_env().app_database_path)
    store.record_claims(real_dataset, hashlib.sha256(args.real.read_bytes()).hexdigest())
    store.record_claims(synthetic_dataset, hashlib.sha256(args.synthetic.read_bytes()).hexdigest())
    print("CyberTrace Neo4j load complete.")


if __name__ == "__main__":
    main()
