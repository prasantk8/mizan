# UC-2: one-command Memtara + Mizan walkthrough

This Technical Preview uses Memtara's real `wealth_suitability` reference prover, not a token
fixture. It then asks Mizan to recommend the same ISIN, clears the two-domain supervisor quorum,
executes once, exports one cross-anchored evidence bundle, and runs both offline verifiers.

## Prerequisites

1. Complete Mizan's installation and start Docker.
2. Clone `memtara-zkp` beside this repository and complete its quickstart.
3. Keep Memtara running. Retain the quickstart's organisation API key, user id, and client vault.

The demo defaults to `http://127.0.0.1:8080`, `../memtara-zkp`, ISIN `XS2500000018`, and
`cro_demo/client_42_vault.json`. Override those paths explicitly when the repositories are elsewhere.

## Run

```bash
MEMTARA_URL=http://127.0.0.1:8080 \
MEMTARA_REPO=../memtara-zkp \
MEMTARA_ORG_API_KEY='<quickstart org key>' \
MEMTARA_USER_ID='<quickstart user id>' \
MEMTARA_VAULT_PATH=cro_demo/client_42_vault.json \
make demo-memtara
```

The Memtara URL is pinned as both the trusted issuer and JWKS source before Mizan starts. The
compact proof token is never printed or exposed to Cedar. Mizan records it only inside the signed
evidence projection so an auditor can re-check its Ed25519 signature offline; treat the resulting
bundle as containing the subject identifiers present in the attestation.

Success ends with both verifiers reporting `VALID`. Stop and remove the demo-only Mizan database and
local evidence with `make demo-down`.

## The backup transcript

`tests/fixtures/demo_memtara/transcript.txt` is the milestone sequence for the backup demo. It is a
**recording**, never a hand-written script: `--write-reference-transcript` writes only what a
completed journey emitted, with per-run identifiers normalised, so there is no way to commit a
transcript describing a walk that did not happen. Note that it covers the walk itself — the export
and the two verifiers run in `scripts/demo.sh` around it, so they are outside the recording.

`tests/unit/test_demo_memtara_walk.py` re-runs the whole journey against fake Memtara and Mizan
edges on every CI run and compares what it records to the committed file, so renaming, reordering or
dropping a milestone turns the suite red. Regenerate it from that run — deliberately, and review the
diff as a change to what the demo claims:

```bash
MIZAN_UPDATE_TRANSCRIPT=1 uv run pytest tests/unit/test_demo_memtara_walk.py
git diff -- tests/fixtures/demo_memtara/transcript.txt
```

Passing `--write-reference-transcript` to a real run against live Memtara and Mizan writes the same
file from that run instead.

This demonstrates the Mizan seam only. Memtara's container/arm64 packaging and reciprocal
DecisionEvidence enrichment remain tracked by M-01 through M-06; do not describe this preview as
bank-pilot-ready or regulator-certified.
