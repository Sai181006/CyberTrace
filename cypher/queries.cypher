// Query 1: malware documented or generated as used by a selected threat actor.
MATCH (a:ThreatActor)-[r:USES]->(m:Malware)
WHERE a.name = $name
RETURN a, r, m;

// Query 2: techniques associated with selected malware.
MATCH (m:Malware)-[r:USES]->(t:Technique)
WHERE m.name = $name
RETURN m, r, t;

// Query 3: organizations targeted by a selected actor.
MATCH (a:ThreatActor)-[r:TARGETS]->(o:Organization)
WHERE a.name = $name
RETURN a, r, o;

// Query 4: malware-to-vulnerability links.
MATCH (m:Malware)-[r:EXPLOITS]->(v:Vulnerability)
RETURN m, r, v;

// Query 5: bounded infrastructure traversal.
MATCH path = (m:Malware)-[:COMMUNICATES_WITH]->(i:IP)-[:RESOLVES_TO]->(d:Domain)
RETURN path;
// Query 6: actor-to-domain investigation path.
MATCH path = (a:ThreatActor)-[:USES]->(m:Malware)-[:COMMUNICATES_WITH]->(i:IP)-[:RESOLVES_TO]->(d:Domain)
WHERE a.name = $name
RETURN path;
