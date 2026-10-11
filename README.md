# CyberTrace

CyberTrace is a local threat-intelligence graph for the BCSE302P Database Systems Lab. It uses Neo4j for graph storage, Flask for the API, and a browser-based interface for exploration. It combines a traceable subset of MITRE ATT&CK Enterprise v19.2 with clearly marked synthetic demonstration data. You can search and explore entities, manage synthetic nodes and relationships, run ten named Cypher investigations, find bounded shortest paths, and inspect directed PageRank results.

## Status and evidence

The end-to-end verification command passed on 11 October 2026: 27 automated tests, 159 nodes, 1,116 relationships, seven labels, six relationship types, seven uniqueness constraints, six explicit search indexes, ten investigations, CRUD, shortest path, and PageRank. See the [final verification record](docs/final-verification.md) and [user manual](docs/user-manual.md) for the checks and walkthrough.

## Architecture

- `frontend/`: responsive HTML, CSS, and JavaScript interface with an SVG neighborhood graph and textual connection list.
- `backend/`: Flask API, local administrator session, Neo4j transaction layer, allowlisted graph services, Cypher investigations, and analytics.
- `data/processed/`: committed, deterministic 105-node MITRE subset. `data/synthetic/`: committed 54-node synthetic fixture. `data/raw/` holds the ignored 53.8 MB upstream STIX bundle when regeneration is needed.
- `scripts/`: import, validation, schema/load, runtime startup, and verification commands.
- `cypher/`: schema and investigation query definitions.
- `docs/` and `output/`: provenance, usage, review material, final report, and demo slides.

The graph has `ThreatActor`, `Malware`, `Technique`, `Vulnerability`, `IP`, `Domain`, and `Organization` labels. Relationship types are `USES`, `TARGETS`, `EXPLOITS`, `COMMUNICATES_WITH`, `RESOLVES_TO`, and `AFFECTS`. The `AFFECTS` links and infrastructure/organization/vulnerability demonstration records are synthetic.

## Requirements

- Python 3.11 or newer.
- Neo4j 5.x reachable via Bolt. The current development machine has an ignored project-local Neo4j Community 5.26.31 and Java 21 runtime in `.runtime/`; these binaries are **not** part of the repository. You may instead use your own Neo4j 5.x installation and set its URI/credentials in `.env`.
- A local browser. The Flask development server binds to `127.0.0.1` by default and is not intended for public deployment.

## Setup and run

From the repository root in PowerShell:

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m scripts.generate_admin_credentials
```

Copy the three generated `CYBERTRACE_` lines into the ignored `.env` file and save the one-time password outside the repository. Set `NEO4J_PASSWORD` and, if needed, `NEO4J_URI`, `NEO4J_USERNAME`, and `NEO4J_DATABASE`. The app refuses to start without both the administrator hash and session secret. Never commit `.env` or the plaintext password.

Start your Neo4j installation. On the prepared development machine, `powershell -ExecutionPolicy Bypass -File scripts/start_neo4j.ps1` starts the ignored project-local runtime. That script checks for its exact `.runtime/` paths and will not install Neo4j for a fresh clone.

```powershell
python -m scripts.validate_data
python -m scripts.load_neo4j
python -m backend.app
```

Open `http://127.0.0.1:5000` and sign in with the generated `admin` credential. The interface provides search, entity details and provenance, an interactive neighborhood graph, investigation queries, shortest-path search, PageRank, and synthetic-record management. `scripts.load_neo4j` is idempotent for the committed fixture; it creates constraints and indexes and uses stable identifiers with `MERGE`.

The committed processed and synthetic fixtures are sufficient for a fresh installation; downloading source data is not required to run the app. To regenerate the real subset, download the exact upstream STIX bundle listed in `data/source-manifest.json` to its listed `local_path`, verify the SHA-256, then run `python -m scripts.import_mitre`. Run `python -m scripts.generate_synthetic` to regenerate the synthetic fixture. Follow either regeneration with `python -m scripts.validate_data` and `python -m scripts.load_neo4j`.

For a deliberate reset, use a disposable, dedicated Neo4j instance, recreate its default database through Neo4j's supported administration workflow, and rerun `scripts.load_neo4j`. **Do not delete an existing shared database** or assume the loader removes unrelated records. Verify the target instance before loading.

## Final verification

With Neo4j running and `.env` configured:

```powershell
python -m scripts.verify_final
```

This runs the automated suite, generated-data validation, live schema/count checks, CRUD, all ten Cypher investigations, generic entity/link management with real-record protection, shortest path, and PageRank. Expected final line: `CYBERTRACE FINAL VERIFICATION READY`.

## Security and data interpretation

The single local administrator uses a scrypt password hash, an HTTP-only same-site session cookie, one-hour session lifetime, and CSRF tokens for writes. The health endpoint is public. This is a lab application, not an internet-facing multi-user security product; keep `FLASK_HOST=127.0.0.1` and `FLASK_DEBUG=false`.

Imported real ATT&CK records are read-only through the API. Manual entities and links are always synthetic. A graph path can mix real and synthetic steps; inspect the provenance of every element. PageRank measures prominence in the stored directed graph, **not** maliciousness or severity. The real-only PageRank scope excludes synthetic nodes and relationships.

See [data provenance](docs/data-provenance.md) and [third-party notices](THIRD_PARTY_NOTICES.md). The [MITRE ATT&CK v19.2 release](https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2) and [MITRE terms](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) are the upstream references.
