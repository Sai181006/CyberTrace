# CyberTrace User Manual

CyberTrace is a local lab application for exploring a threat-intelligence graph. It combines a documented MITRE ATT&CK subset with synthetic infrastructure and scenario data. Read the `Source` and `Synthetic` fields before drawing conclusions from a result.

## Start and sign in

1. Start Neo4j and the Flask app using the commands in `README.md`.
2. Open `http://127.0.0.1:5000`. The status badge should say `Neo4j connected`.
3. Enter the local administrator username and the one-time password saved during setup. Click **Sign in**.
4. If the database status is unavailable, check the Bolt URI, database credentials, and Neo4j process. The health endpoint remains accessible at `/api/health` without sign-in.

The login protects the data API. Sessions expire after one hour. Use **Sign out** when finished. The password is not stored in the repository; to rotate it, generate a new hash and secret with `python -m scripts.generate_admin_credentials` and replace the corresponding ignored `.env` values, then restart Flask.

## Read the dashboard

The Dashboard shows live node and relationship totals, counts by label, and a real-versus-synthetic node split. **Refresh** re-queries Neo4j. The baseline loaded fixture has 159 nodes and 1,116 relationships; manual changes can alter these totals.

## Search and inspect provenance

Open **Threat Search**. Enter a name or part of a name, address, or CVE identifier, optionally choose an entity type, and click **Search**. A result shows its stable ID, source, synthetic status, and a short description. Open **Full details and provenance** for the complete property record.

For a real example, search `APT28`. Its stable actor ID is `G0007`, its source is MITRE ATT&CK, and `is_synthetic` is false. Real records are read-only. Search `c2-demo` to see synthetic example domains.

## Explore connections

Open **Graph Explorer**, select `ThreatActor`, enter `G0007`, and click **Explore**. The SVG shows a center node and up to twelve immediate neighbors. The connection list below is keyboard-operable and identifies node type, relationship, and real/synthetic status. Select a listed connection to inspect properties. The service bounds the neighborhood to avoid an unmanageable graph.

## Manage synthetic data

Open **Manage Data**. Select one of the seven entity types, enter its stable ID, and write a JSON object with only the fields listed under the form. Example for a `Malware` entity:

```json
{"name":"Training Sample","description":"Synthetic lab record","severity":"Medium"}
```

Use **Create** to add it. The system automatically writes `source= Synthetic` and `is_synthetic=true`. Use **Read** to load a record and its editable fields. **Update** and **Delete** first display the current record and a provenance confirmation. Imported real records cannot be changed. Deleting a synthetic node also deletes its attached relationships through Neo4j `DETACH DELETE`, so inspect it first.

To create a relationship, choose an allowed directed pattern, enter both stable endpoint IDs, and click **Create link**. Copy the returned `MANUAL-...` relationship ID. Use **Read link** to inspect endpoints and provenance. **Delete link** only accepts synthetic relationships and asks for confirmation. Manual links can connect to real imported nodes but remain synthetic claims.

For a safe practice pair, create `IP` ID `SYN-PRACTICE-IP` with `{"address":"192.0.2.242"}` and `Domain` ID `SYN-PRACTICE-DOMAIN` with `{"name":"practice.example.org"}`. Create an `IP → RESOLVES_TO → Domain` link between them. These use reserved documentation values. Remove the link and nodes when finished.

## Investigate a multi-hop chain

Open **Investigation**, enter `APT28`, and click **Investigate**. Results show three relationship steps from actor to malware, IP, and domain. The actor and malware links may come from ATT&CK, while the infrastructure portion is synthetic. Do not present the entire chain as a confirmed incident.

## Run graph analytics

On **Analytics**, the shortest-path form accepts two types, two stable IDs, and a maximum of one to six hops. For a known one-hop example, use `ThreatActor G0007` and `Organization SYN-ORG-001`: the `TARGETS` relationship is synthetic. A missing endpoint produces an error; two existing entities with no path within the hop limit produce a no-path message. The service traverses relationships in either direction and displays their stored direction and provenance in the API.

**PageRank** uses directed stored relationships. Choose **Real ATT&CK records only** or **Real and synthetic records**, then click **Calculate PageRank**. The result includes the scope, node and relationship counts, convergence iteration count, score, and provenance. A higher PageRank means more graph prominence under this model; it does not mean a higher threat level.

## Troubleshooting and limits

- `Sign in is required`: the session expired; sign in again.
- `A valid CSRF token is required`: refresh the page and sign in again before changing data.
- `Database operation failed`: check Neo4j connectivity and credentials, then retry.
- `Real imported entities are read-only`: use a new synthetic ID for a demonstration change.
- A path may mix real and synthetic elements. Inspect each link's `source` and `is_synthetic` value.
- The local administrator system has no roles, password reset email, or remote hardening. Do not expose the development server to the internet.
