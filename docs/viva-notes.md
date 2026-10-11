# CyberTrace Demo and Viva Notes

## Eight minute demonstration

1. Start with the local sign-in and show the dashboard: 159 nodes, 1,116 relationships, 105 real nodes, and 54 synthetic nodes in the baseline fixture.
2. Search `APT28`. Open full details to show `G0007`, MITRE source URL, v19.2 dataset version, and `is_synthetic=false`.
3. Explore `ThreatActor G0007`. Use the keyboard-accessible connection list and point out that the view is bounded to twelve visible neighbors.
4. In Manage Data, show a synthetic malware record's JSON fields and provenance. Demonstrate create/read/update/delete on a disposable `SYN-...` ID. State that real imported nodes cannot be edited.
5. Investigate `APT28` to show actor, malware, IP, and domain. State that the infrastructure link is synthetic.
6. Find a one-hop path from `ThreatActor G0007` to `Organization SYN-ORG-001`; the `TARGETS` edge is synthetic. Then show PageRank real-only and all-data scopes.
7. Run `python -m scripts.verify_final` and show the final readiness line.

## Likely questions

**Why Neo4j rather than a relational table?** The core questions traverse several relationship types and variable-length paths. Cypher makes those relationships explicit, while stable IDs and constraints preserve data integrity. A relational model is possible, but repeated joins would obscure the lab's graph questions.

**What is the schema?** Seven node labels, six distinct relationship types, and nine allowed directed label patterns. The implementation creates uniqueness constraints on seven stable IDs and six search indexes.

**Which data is real?** Only the pinned MITRE ATT&CK Enterprise v19.2 subset and its documented `USES` links. Real records retain source identifiers, URLs, version, and a false synthetic flag. Infrastructure, organizations, vulnerabilities, and additional scenario links are synthetic.

**Why mix real and synthetic data?** MITRE's selected subset alone does not provide the complete actor-to-infrastructure demonstration path. The synthetic layer supplies a safe, repeatable teaching scenario without claiming that those connections are true incidents.

**How is CRUD safe?** Entity labels and mutable fields are allowlisted; relationship patterns are allowlisted; Cypher values are parameters. Manual writes force synthetic provenance. Imported real entities and relationships are read-only. Neo4j driver-managed transactions execute writes.

**Why indexes and constraints?** Uniqueness constraints prevent duplicate stable IDs and accelerate ID lookup. Search indexes target common name/address/CVE fields. The loader uses `MERGE` so rerunning it does not duplicate fixture records.

**How does shortest path work?** It checks both endpoints, then uses bounded Neo4j `shortestPath` with a one-to-six-hop limit. Traversal is undirected to discover a connection; returned edges retain their stored direction and provenance. No path and missing endpoint are distinct states.

**How does PageRank work?** It iterates directed rank flow with damping 0.85, handles dangling nodes, and stops at a convergence tolerance or 100 iterations. The user selects real-only or all-data scope. PageRank indicates prominence inside this selected graph; it is not a danger score.

**What are the limitations?** The real subset is not a complete threat feed; synthetic paths are examples; the graph drawing shows only a neighborhood; local single-user authentication and Flask's development server are not public deployment hardening. The ignored Neo4j runtime must be provisioned separately on a fresh clone.
