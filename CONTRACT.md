# Ingestion contract source

The normative source is Robot requirements commit
`df8682b927f7e05e0c6c9342b66d32e320f038b4`, adopted through requirements PR #316
for MVP-152 / GH-203.1.

`schemas/ingestion.json` copies the four definitions from
`contracts/openapi/components/github-release-ingestion.yaml` into `$defs`.
This is generated consumer material, not a competing API definition. Update it
only from the adopted canonical source and rerun producer/consumer tests.

Operations are OIDC-only `POST /api/v1/github/release-ingestions` and
`POST /api/v1/github/release-ingestions/{release_id}/finalize`. The latter
retains HTTP 202 with an in-band result; success is `READY_TO_SIGN`, never the
HTTP status alone. Original evidence and tenant authority survive replay.

This repository is an implementation candidate. `v1.0.0` is withheld until
the matching backend is deployed and the protected-tag/private-Docker smoke
qualification succeeds. Local controlled tests do not establish live acceptance.
