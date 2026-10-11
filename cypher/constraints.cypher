CREATE CONSTRAINT threatactor_actor_id_unique IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.actor_id IS UNIQUE;
CREATE CONSTRAINT malware_malware_id_unique IF NOT EXISTS FOR (n:Malware) REQUIRE n.malware_id IS UNIQUE;
CREATE CONSTRAINT technique_technique_id_unique IF NOT EXISTS FOR (n:Technique) REQUIRE n.technique_id IS UNIQUE;
CREATE CONSTRAINT vulnerability_cve_id_unique IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE;
CREATE CONSTRAINT ip_ip_id_unique IF NOT EXISTS FOR (n:IP) REQUIRE n.ip_id IS UNIQUE;
CREATE CONSTRAINT domain_domain_id_unique IF NOT EXISTS FOR (n:Domain) REQUIRE n.domain_id IS UNIQUE;
CREATE CONSTRAINT organization_organization_id_unique IF NOT EXISTS FOR (n:Organization) REQUIRE n.organization_id IS UNIQUE;
