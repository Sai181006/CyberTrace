"""Create CyberTrace constraints and indexes in an idempotent way."""

from __future__ import annotations

from backend.config import Settings
from backend.db import Neo4jDatabase
from backend.schema import all_schema_statements


def main() -> None:
    database = Neo4jDatabase(Settings.from_env())
    try:
        database.verify_connectivity()
        statements = all_schema_statements()
        for position, statement in enumerate(statements, start=1):
            database.run_schema_statement(statement)
            print(f"[{position:02}/{len(statements):02}] applied: {statement}")
        print("CyberTrace schema setup complete.")
    finally:
        database.close()


if __name__ == "__main__":
    main()
