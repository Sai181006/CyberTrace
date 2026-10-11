"""Neo4j driver lifecycle and transaction helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from neo4j import Driver, GraphDatabase, ManagedTransaction

from .config import Settings

T = TypeVar("T")


class Neo4jDatabase:
    def __init__(self, settings: Settings) -> None:
        self._database = settings.neo4j_database
        self._driver: Driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_username, settings.neo4j_password),
        )

    def close(self) -> None:
        self._driver.close()

    def verify_connectivity(self) -> None:
        self._driver.verify_connectivity()

    def execute_read(self, work: Callable[[ManagedTransaction], T]) -> T:
        with self._driver.session(database=self._database) as session:
            return session.execute_read(work)

    def execute_write(self, work: Callable[[ManagedTransaction], T]) -> T:
        with self._driver.session(database=self._database) as session:
            return session.execute_write(work)

    def read_query(
        self, query: str, parameters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        def run(tx: ManagedTransaction) -> list[dict[str, Any]]:
            return [record.data() for record in tx.run(query, parameters or {})]

        return self.execute_read(run)

    def write_query(
        self, query: str, parameters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        def run(tx: ManagedTransaction) -> list[dict[str, Any]]:
            return [record.data() for record in tx.run(query, parameters or {})]

        return self.execute_write(run)

    def run_schema_statement(self, statement: str) -> dict[str, Any]:
        def run(tx: ManagedTransaction) -> dict[str, Any]:
            result = tx.run(statement)
            summary = result.consume()
            summary_database = summary.database
            return {
                "query_type": str(summary.query_type),
                "database": (
                    getattr(summary_database, "name", summary_database)
                    if summary_database
                    else self._database
                ),
            }

        return self.execute_write(run)
