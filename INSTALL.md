# Install Mizan on a clean machine

This is the supported single-node production pilot path. It uses Docker Compose, customer-issued
TLS material, HashiCorp Vault Transit, PostgreSQL, and an S3-compatible bucket with Object Lock in
COMPLIANCE mode. It does not create a private CA, a Vault root token, an IdP, or a timestamp
authority. Those trust roots remain customer controlled.

## 1. Prerequisites

- A clean Linux or macOS host with Git, Docker Engine/Desktop (Compose v2), Python 3.12+, `uv`,
  OpenSSL, and `curl`.
- A TLS-enabled Vault endpoint and a provisioning token allowed to mount Transit and create keys.
- A separate runtime Vault token allowed to read keys and sign, supplied in a file.
- An S3-compatible endpoint and credentials allowed to create/configure one Object Lock bucket.
- Customer-issued server and health-probe certificates, their keys and CA bundles.
- An RFC 3161 HTTPS endpoint and its trust root.
- A customer IdP issuer and public JWKS. T-132 adds the browser OIDC client to this same guide.

Verify the checkout before handling credentials:

```sh
git clone https://github.com/prasantk8/mizan.git
cd mizan
git status --short
uv sync --locked --dev
make check
```

## 2. Assemble the credential layout

Never pass the Vault token on the command line and never copy private keys into Git. The bootstrap
script refuses an existing output directory unless `--force` is explicit, validates both key pairs,
copies private material with mode `0600`, and generates independent PostgreSQL passwords.

```sh
scripts/bootstrap_credentials.sh --output secrets \
  --server-cert /customer-pki/mizan-server.pem \
  --server-key /customer-pki/mizan-server-key.pem \
  --client-ca /customer-pki/workload-client-ca.pem \
  --server-ca /customer-pki/server-ca.pem \
  --health-client-cert /customer-pki/health-client.pem \
  --health-client-key /customer-pki/health-client-key.pem \
  --tsa-root /customer-pki/tsa-root.pem \
  --vault-ca /customer-pki/vault-ca.pem \
  --vault-token-file /customer-secrets/mizan-vault-runtime-token
```

Edit `secrets/.env.production`. Replace every `replace-…` value, set the public-only identity
JWKS on one line, name the tenant set served by both workers, and use scoped S3 runtime credentials.
The file and `secrets/` are ignored by Git; confirm with `git status --short`.

## 3. Provision the four non-exportable Vault Transit keys

Use a provisioning token, not the runtime token copied above:

```sh
export VAULT_ADDR=https://vault.customer.example:8200
export VAULT_CACERT=/customer-pki/vault-ca.pem
read -rsp 'Vault provisioning token: ' VAULT_TOKEN; export VAULT_TOKEN; printf '\n'
bash scripts/provision_vault.sh
unset VAULT_TOKEN
```

The script creates Ed25519 keys with `exportable=false` and prints pinned `#v1` references. Its
default names already match `compose.production.yaml`; copy different prefixes/versions into
`secrets/.env.production` only when you deliberately changed them.

## 4. Create and verify the Object Lock bucket

Load the non-secret variables and inject the S3 secret through your shell or secret manager:

```sh
set -a; . secrets/.env.production; set +a
read -rsp 'S3 runtime secret: ' MIZAN_S3_SECRET_ACCESS_KEY; export MIZAN_S3_SECRET_ACCESS_KEY; printf '\n'
uv run --frozen python scripts/provision_object_store.py \
  --bucket "$MIZAN_AUDIT_ANCHOR_BUCKET" \
  --endpoint-url "$MIZAN_S3_ENDPOINT_URL" \
  --region "$MIZAN_S3_REGION" --retention-years 7
unset MIZAN_S3_SECRET_ACCESS_KEY
```

The command must print `PASS` with Object Lock `Enabled` and COMPLIANCE retention. An ordinary
bucket cannot be upgraded in place; create a new bucket if this check fails.

## 5. Start and prove readiness

```sh
docker compose --env-file secrets/.env.production \
  --profile production -f compose.production.yaml up -d --build --wait
curl --fail --silent --show-error \
  --cacert secrets/tls/server-ca.pem \
  --cert secrets/tls/health-client.pem \
  --key secrets/tls/health-client-key.pem \
  https://127.0.0.1:8443/readyz | python3 -m json.tool
```

Do not proceed unless the response has `"status": "ready"` and every check is `"ok"`. Inspect
`docker compose ... ps` and `docker compose ... logs` on failure. Stop without deleting data:

```sh
docker compose --env-file secrets/.env.production \
  --profile production -f compose.production.yaml down
```

Do not add `--volumes` on a production host. Backup and recovery are exercised by T-130's runbook.

## 6. Walkthrough acceptance

A maintainer run is preflight, not acceptance. Give this file to a named person outside the build
team on a machine the build team did not prepare. They record commands, timings, failures and every
correction in `docs/reviews/CP-F-WALKTHROUGH.md`, apply the corrections in this repository, then
repeat the full run from a fresh machine state. T-129 is not complete until that rerun is green.

