"""One-command final verification for code, data, live Neo4j, and analytics."""

from __future__ import annotations

import pytest

from scripts.verify_analytics import main as verify_analytics
from scripts.verify_management import main as verify_management
from scripts.verify_review2 import main as verify_review2


def main() -> None:
    print("=== Automated tests (including authentication and CSRF) ===")
    result = pytest.main(["-q", "-p", "no:cacheprovider", "tests"])
    if result != 0:
        raise SystemExit(result)
    print("\n=== Review 2 regression ===")
    verify_review2()
    print("\n=== Generic management and real-data guard ===")
    verify_management()
    print("\n=== Review 3 analytics ===")
    verify_analytics()
    print("\nCYBERTRACE FINAL VERIFICATION READY")


if __name__ == "__main__":
    main()
