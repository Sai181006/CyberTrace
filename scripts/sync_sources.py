"""Fetch and merge official ATT&CK and CISA KEV feeds with an audit trail."""

from __future__ import annotations

import argparse
import json

from backend.config import Settings
from backend.data.feeds import SOURCES, sync_source
from backend.db import Neo4jDatabase
from backend.store import AppStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["all", *SOURCES], default="all")
    parser.add_argument("--force", action="store_true", help="Reapply unchanged content, for example after rebuilding Neo4j")
    args = parser.parse_args()
    settings = Settings.from_env()
    store = AppStore(settings.app_database_path)
    database = Neo4jDatabase(settings)
    try:
        database.verify_connectivity()
        for source in (SOURCES if args.source == "all" else [args.source]):
            print(json.dumps(sync_source(database, store, source, force=args.force), indent=2))
    finally:
        database.close()


if __name__ == "__main__":
    main()
