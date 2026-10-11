"""Print one-time local administrator settings without writing credentials to disk."""

from __future__ import annotations

import secrets

from werkzeug.security import generate_password_hash


def main() -> None:
    password = secrets.token_urlsafe(18)
    print("Add these lines to your ignored .env file:")
    print("CYBERTRACE_ADMIN_USERNAME=admin")
    print(
        f"CYBERTRACE_ADMIN_PASSWORD_HASH={generate_password_hash(password, method='scrypt')}"
    )
    print(f"CYBERTRACE_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"One-time admin password (save securely): {password}")


if __name__ == "__main__":
    main()
