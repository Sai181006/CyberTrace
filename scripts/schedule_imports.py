"""Run official-source sync periodically in a dedicated process."""

from __future__ import annotations

import argparse
import time

from backend.config import Settings
from backend.data.feeds import SOURCES, sync_source
from backend.db import Neo4jDatabase
from backend.store import AppStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval-hours", type=float, default=24)
    parser.add_argument("--source", choices=["all", *SOURCES], default="all")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.interval_hours <= 168:
        parser.error("--interval-hours must be between 1 and 168")
    settings = Settings.from_env()
    store = AppStore(settings.app_database_path)
    database = Neo4jDatabase(settings)
    try:
        while True:
            for source in (SOURCES if args.source == "all" else [args.source]):
                try:
                    result = sync_source(database, store, source)
                    print(f"{source}: {result['status']} ({result['version']})", flush=True)
                except Exception as exc:
                    print(f"{source}: failed: {exc}", flush=True)
            if args.once:
                break
            time.sleep(args.interval_hours * 3600)
    finally:
        database.close()


if __name__ == "__main__":
    main()
