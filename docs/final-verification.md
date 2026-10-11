# Final Verification Record

Observed on 11 October 2026 in the project workspace with Neo4j Community 5.26.31 running locally. Command: `python -m scripts.verify_final` (under the project's pinned Python requirements).

| Check | Observed result |
| --- | --- |
| Automated tests | 27 passed, including login, CSRF, configuration failure, and analytics |
| Generated data validation | PASS |
| Live graph | 159 nodes and 1,116 relationships |
| Provenance | 105 real nodes, 54 synthetic nodes |
| Schema | 7 labels, 6 relationship types, 7 uniqueness constraints, 6 explicit search indexes |
| Multi-hop actor investigation | 90 complete paths in the loaded graph |
| Review 2 CRUD | Create, read, update, search, delete, and deletion verification passed |
| Named Cypher investigations | All 10 passed |
| Generic management | 7 entity types, 9 allowed link patterns, entity and relationship operations passed |
| Real-record guard | Attempted APT28 update returned HTTP 403; its name remained APT28 |
| Shortest path | 3 relationships on an actor-to-domain example; 1-hop no-path and missing endpoint cases passed |
| PageRank real scope | 105 nodes, 1,038 directed relationships, converged in 26 iterations |
| PageRank all scope | 159 nodes, 1,116 directed relationships, converged in 23 iterations |

The final command ended with `CYBERTRACE FINAL VERIFICATION READY`. `ruff check backend scripts tests` and `node --check frontend/app.js` also passed. Browser checks covered local sign-in and sign-out, dashboard, APT28 search and graph, keyboard-accessible graph connections, investigation, a one-hop path, PageRank at narrow width, and the real-record read-only state. Those browser checks do not replace a formal accessibility audit or cross-browser test.

The verification scripts create only named synthetic temporary records and remove them after testing. Live totals above describe the baseline fixture, not an immutable production dataset. Re-run the command after environment or code changes.
