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
local evidence with `make demo-down`. The committed backup transcript is
`tests/fixtures/demo_memtara/transcript.txt`; regenerate it with:

```bash
uv run python scripts/demo_memtara_walk.py \
  --write-reference-transcript tests/fixtures/demo_memtara/transcript.txt
git diff --exit-code -- tests/fixtures/demo_memtara/transcript.txt
```

This demonstrates the Mizan seam only. Memtara's container/arm64 packaging and reciprocal
DecisionEvidence enrichment remain tracked by M-01 through M-06; do not describe this preview as
bank-pilot-ready or regulator-certified.
