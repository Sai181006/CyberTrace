from backend.schema import (
    all_schema_statements,
    constraint_statements,
    index_statements,
)


def test_schema_statement_counts() -> None:
    assert len(constraint_statements()) == 7
    assert len(index_statements()) == 7
    assert len(all_schema_statements()) == 14


def test_schema_setup_is_idempotent() -> None:
    assert all("IF NOT EXISTS" in statement for statement in all_schema_statements())
