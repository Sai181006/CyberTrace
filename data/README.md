# CyberTrace data

## Real source

The initial real-data source is the official MITRE ATT&CK Enterprise v19.2 STIX 2.1 bundle released on 5 August 2026. Its immutable project pin, retrieval time, file size, bundle identity, and SHA-256 checksum are recorded in `source-manifest.json`.

The large raw file is intentionally ignored by Git. Download it from the exact `download_url` in the manifest and verify its SHA-256 value before running the importer. The deterministic, manageable output is committed as `processed/mitre-attack-subset.json` so the Review 2 demo works offline.

The source contains real-world knowledge curated by MITRE, but CyberTrace must not imply that MITRE endorses this project.

## Synthetic data

Synthetic data will be generated locally and deterministically. It is not part of the MITRE ATT&CK bundle and must never use MITRE provenance fields. Synthetic records are reserved for organizations, documentation-safe IP addresses, example domains, and relationships needed to demonstrate an end-to-end path.

The frozen Review 2 fixture is committed as `synthetic/synthetic-demo.json` and can be reproduced with `python -m scripts.generate_synthetic` using seed 302.

## Attribution

MITRE ATT&CK data is used under MITRE's terms of use. Any redistributed ATT&CK-derived data must retain the copyright designation and license described in `THIRD_PARTY_NOTICES.md`.
