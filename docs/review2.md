# CyberTrace Review 2 Evidence

## 1. Database implementation - 2 marks

Evidence:

- Neo4j Community 5.26.31 runs locally with Bolt on `localhost:7687`.
- `scripts/load_neo4j.py` creates the schema and idempotently loads validated data.
- Live database: 159 nodes and 1,116 relationships.
- Seven node labels: `ThreatActor`, `Malware`, `Technique`, `Vulnerability`, `IP`, `Domain`, and `Organization`.
- Six relationship types: `USES`, `TARGETS`, `EXPLOITS`, `COMMUNICATES_WITH`, `RESOLVES_TO`, and `AFFECTS`.
- Seven uniqueness constraints, six explicit search indexes, and seven constraint-backed indexes.
- The real subset contains 105 MITRE ATT&CK Enterprise v19.2 nodes and 1,038 documented `USES` relationships.
- The controlled synthetic layer contains 54 nodes and 78 relationships, all visibly marked synthetic.

Demonstration command:

```powershell
python -m scripts.verify_database
```

## 2. CRUD operations - 3 marks

Evidence:

- `POST /api/entities` creates an allowlisted entity and forces manual provenance to synthetic.
- `GET /api/entities/<type>/<id>` reads an entity by stable identifier.
- `PUT /api/entities/<type>/<id>` updates only mutable, allowlisted properties.
- `DELETE /api/entities/<type>/<id>` safely uses `DETACH DELETE`.
- `POST /api/relationships` and `DELETE /api/relationships/<id>` provide relationship CRUD.
- The Manage Data UI provides the `ReviewDemoMalware` demonstration workflow.
- `scripts/verify_crud.py` performs create, read, update, search, delete, and deletion verification against live Neo4j.

Demonstration command:

```powershell
python -m scripts.verify_crud
```

## 3. Advanced NoSQL features - 5 marks

Evidence:

- Ten named, parameterized Cypher investigations are implemented in `backend/investigations.py`.
- A live actor-to-malware-to-IP-to-domain traversal returns 90 valid multi-hop paths.
- The Graph Explorer visualizes a selected node, immediate neighbors, relationship types, and properties.
- Strict label/property/relationship allowlists prevent schema injection; values remain Cypher parameters.
- Driver-managed read/write transactions are used throughout the backend.
- The dashboard displays live database and provenance aggregations.
- `scripts/verify_queries.py` executes all ten investigation queries against Neo4j.

Demonstration command:

```powershell
python -m scripts.verify_queries
```

## One-command verification

With Neo4j running and `.env` configured:

```powershell
python -m scripts.verify_review2
```

Expected final line:

```text
CYBERTRACE REVIEW 2 READY
```

## Suggested live demonstration order

1. Open `http://127.0.0.1:5000` and show the dashboard totals and provenance split.
2. Search for `APT28` and show its MITRE ATT&CK source fields.
3. Open Graph Explorer with `ThreatActor` / `G0007` and inspect connected malware and techniques.
4. Use Manage Data to create, read, update, and delete `SYN-REVIEW-DEMO`.
5. Run the multi-hop Investigation page for a connected actor.
6. Run `python -m scripts.verify_review2` and show all PASS results.
