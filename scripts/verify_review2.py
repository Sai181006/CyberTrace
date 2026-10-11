"""Run the complete CyberTrace Review 2 verification sequence."""

from scripts.validate_data import main as validate_data
from scripts.verify_crud import main as verify_crud
from scripts.verify_database import main as verify_database
from scripts.verify_queries import main as verify_queries


def main() -> None:
    print("=== 1. Generated data ===")
    validate_data()
    print("\n=== 2. Live Neo4j database ===")
    verify_database()
    print("\n=== 3. CRUD workflow ===")
    verify_crud()
    print("\n=== 4. Cypher investigations ===")
    verify_queries()
    print("\nCYBERTRACE REVIEW 2 READY")


if __name__ == "__main__":
    main()
