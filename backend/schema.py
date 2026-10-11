"""Fixed schema statements for the supported CyberTrace graph model."""

NODE_IDENTIFIERS = {
    "ThreatActor": "actor_id",
    "Malware": "malware_id",
    "Technique": "technique_id",
    "Vulnerability": "cve_id",
    "IP": "ip_id",
    "Domain": "domain_id",
    "Organization": "organization_id",
}

SEARCHABLE_FIELDS = {
    "ThreatActor": "name",
    "Malware": "name",
    "Technique": "name",
    "Vulnerability": "cve_id",
    "IP": "address",
    "Domain": "name",
    "Organization": "name",
}


def constraint_statements() -> list[str]:
    return [
        (
            f"CREATE CONSTRAINT {label.lower()}_{property_name}_unique IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.{property_name} IS UNIQUE"
        )
        for label, property_name in NODE_IDENTIFIERS.items()
    ]


def index_statements() -> list[str]:
    return [
        (
            f"CREATE INDEX {label.lower()}_{property_name}_index IF NOT EXISTS "
            f"FOR (n:{label}) ON (n.{property_name})"
        )
        for label, property_name in SEARCHABLE_FIELDS.items()
    ]


def all_schema_statements() -> list[str]:
    return [*constraint_statements(), *index_statements()]
