# Publish a Robot release candidate

Use `RobotsCI/publish-release` after your workflow has built its Linux application
and generated its SBOM. The Action succeeds only when Robot independently
verifies the candidate as **READY_TO_SIGN**. Signing and device deployment are
separate operations.

**Implementation candidate:** the backend must support the MVP-152 ingestion
contract. Version `v1.0.0` awaits matching deployed qualification; see
[the contract source and release gate](CONTRACT.md).

## Requirements

- A ready Robot GitHub App connection for this repository, workflow and protected tag.
- A Linux amd64 runner with Docker, Python 3.10 or newer and Bash. Target application bytes
  may be **arm64** (including Jetson) or **amd64**; the Action does not build or
  cross-compile them.
- An existing tar.gz application artifact and a truthful CycloneDX **1.5** JSON
  SBOM. Include the artifact SHA-256 in `metadata.component.hashes` using
  `alg: SHA-256`. Both files must resolve inside `GITHUB_WORKSPACE`. Their bytes
  are preserved. Artifacts are limited to 5 GiB and SBOM JSON to 16 MiB.
- A dedicated Docker Hub evidence repository and a scoped publishing token stored
  in GitHub Actions secrets. The API uses that credential only for request-scoped
  private evidence verification; it never persists it.

## Workflow

Pin the Action to the full reviewed commit SHA recorded in its release. Replace
the build command with your own, producing the two files shown below.

```yaml
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  id-token: write

jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      - run: ./ci/build-release.sh # Creates dist/application.tar.gz and dist/sbom.cdx.json
      - id: release
        uses: RobotsCI/publish-release@REPLACE_WITH_REVIEWED_FULL_COMMIT_SHA
        with:
          api-base-url: https://YOUR_ROBOT_API_ORIGIN
          oidc-audience: YOUR_CONFIGURED_RELEASE_AUDIENCE
          release-version: ${{ github.ref_name }}
          artifact-path: dist/application.tar.gz
          sbom-path: dist/sbom.cdx.json
          target-architecture: arm64
          min-agent-version: '1.0.0'
          oci-artifact-reference: docker.io/YOUR_NAMESPACE/YOUR_EVIDENCE_REPOSITORY:release-${{ github.sha }}
          dockerhub-username: ${{ vars.DOCKERHUB_USERNAME }}
          dockerhub-token: ${{ secrets.DOCKERHUB_RELEASE_EVIDENCE_TOKEN }}
```

`release-version` must be a stable version containing letters, digits, `.`, `_`,
`+` or `-` (up to 128 characters). If your tag includes `/`, strip its prefix in
an earlier workflow step; do not pass the slash-containing tag as the version.
The API URL is an HTTPS origin without credentials, path, query or fragment.

## Results and retry behavior

Outputs are `release-id`, `status`, `artifact-sha256`, `sbom-sha256` and
`oci-evidence-reference`. They are emitted only after verified success. The
evidence reference is the **accepted digest reference**, including on replay.
Do not infer signing or deployment from `READY_TO_SIGN`.

Robot derives the organization from verified GitHub source identity. There is
no organization, repository-ID or workflow-ID input. The candidate identity is
repository + commit + artifact digest. Matching publication retries preserve
the original candidate and evidence. Conflicting version, target or SBOM
metadata fails. A different workflow run cannot take over an unfinished
candidate; it may recover a matching terminal result only while current
repository authorization still allows the original source.

Requests retry transient failures at most three times, refresh OIDC identity
and honor numeric Retry-After values up to 60 seconds. A longer/unsupported
delay fails safely for a later workflow retry. Upload ambiguity obtains a new
pair of grants before retrying; consumed URLs are never blindly reused. Robot
retains the original ten-minute grant and 24-hour candidate limits. Rejected
candidates stay rejected; incomplete verification fails rather than reporting
success.

The Action creates keyless provenance/SBOM bundles and publishes exactly four
OCI evidence layers. Its Cosign installer and ORAS image are pinned. Keep
`ACTIONS_STEP_DEBUG` and shell tracing disabled for secret-handling workflows;
do not print inputs or API request/response bodies in your own steps.

## Development

The publisher uses Python's standard library. Run behavioral tests with:

```sh
python3 -m pip install -r tests/requirements.txt
python3 -B -m unittest discover -s tests -v
```

`schemas/ingestion.json` is a narrow generated copy of the canonical Robot
ingestion schemas. `CONTRACT.md` records its source. Live GitHub/private-Docker
acceptance remains a separate qualification from these controlled tests.
