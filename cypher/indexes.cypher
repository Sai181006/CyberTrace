CREATE INDEX threatactor_name_index IF NOT EXISTS FOR (n:ThreatActor) ON (n.name);
CREATE INDEX malware_name_index IF NOT EXISTS FOR (n:Malware) ON (n.name);
CREATE INDEX technique_name_index IF NOT EXISTS FOR (n:Technique) ON (n.name);
CREATE INDEX vulnerability_cve_id_index IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id);
CREATE INDEX ip_address_index IF NOT EXISTS FOR (n:IP) ON (n.address);
CREATE INDEX domain_name_index IF NOT EXISTS FOR (n:Domain) ON (n.name);
CREATE INDEX organization_name_index IF NOT EXISTS FOR (n:Organization) ON (n.name);
