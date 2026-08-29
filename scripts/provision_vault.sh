#!/usr/bin/env bash
# Create the four Ed25519 Transit keys Mizan signs with, and print the configuration to set.
#
# This is the missing half of B-18. The backend is useless without keys, and "create four Ed25519
# keys in Transit" is the kind of instruction that reads as obvious and is wrong in three places:
# the Transit engine has to be mounted first, `type` defaults to `aes256-gcm96` (which cannot
# sign), and a key created with `exportable=true` can be pulled out of Vault -- at which point
# `custody: kms` in every exported bundle becomes a false statement about where the private key
# lives.
#
# Idempotent. Run it against a fresh Vault or an existing one.
#
#   VAULT_ADDR=https://vault.internal:8200 VAULT_TOKEN=... bash scripts/provision_vault.sh
#
# Set VAULT_CACERT when Vault presents a certificate from a private CA, which is the normal case
# for an internal deployment -- and the only case, in production, where MIZAN_VAULT_ADDR must be
# https://.
#
# The token needs: create on sys/mounts/transit, and create+read on transit/keys/*. It does NOT
# need sign -- provisioning and running are different jobs and should be different tokens.

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:?set VAULT_ADDR, e.g. https://vault.internal:8200}"
VAULT_TOKEN="${VAULT_TOKEN:?set VAULT_TOKEN}"
MOUNT="${MIZAN_VAULT_TRANSIT_MOUNT:-transit}"
# A private CA is the normal case for an internal Vault, and production requires https:// -- so a
# provisioning script that could only talk to a publicly-trusted endpoint could not be run against
# the deployment it provisions. Same variable name Vault's own CLI uses.
CACERT="${VAULT_CACERT:-}"
PREFIX="${MIZAN_VAULT_KEY_PREFIX:-mizan}"

api() {
  local method="$1" path="$2" body="${3:-}"
  local -a curl_options=(-sS -X "$method" -H "X-Vault-Token: $VAULT_TOKEN")
  [ -n "$CACERT" ] && curl_options+=(--cacert "$CACERT")
  if [ -n "$body" ]; then
    curl "${curl_options[@]}" -d "$body" "$VAULT_ADDR$path"
  else
    curl "${curl_options[@]}" "$VAULT_ADDR$path"
  fi
}

mounted=$(api POST "/v1/sys/mounts/$MOUNT" '{"type":"transit"}' || true)
if printf '%s' "$mounted" | grep -q '"errors"' && ! printf '%s' "$mounted" | grep -q 'already in use'; then
  printf 'could not mount transit at %s: %s\n' "$MOUNT" "$mounted" >&2
  exit 1
fi

echo "# Mizan signing keys provisioned in Vault Transit at $VAULT_ADDR (mount: $MOUNT)"
echo "#"
echo "# Set these on the control plane, the drain worker and the attestation runner:"
echo "MIZAN_KEY_CUSTODY_MODE=vault-transit"
echo "MIZAN_VAULT_ADDR=$VAULT_ADDR"
[ -n "$CACERT" ] && echo "MIZAN_VAULT_CA_CERT=$CACERT"
echo "# MIZAN_VAULT_TOKEN_FILE=/var/run/secrets/vault/token   # preferred over MIZAN_VAULT_TOKEN"

for pair in \
  "evidence-receipt:MIZAN_EVIDENCE_RECEIPT_KEY_REF" \
  "evidence-anchor:MIZAN_EVIDENCE_ANCHOR_KEY_REF" \
  "execution-token:MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF" \
  "degraded-grant:MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF"
do
  role="${pair%%:*}"
  variable="${pair##*:}"
  name="$PREFIX-$role"
  # `exportable` and `allow_plaintext_backup` are left at their false defaults deliberately and
  # named here so that nobody adds them later thinking they are conveniences.
  created=$(api POST "/v1/$MOUNT/keys/$name" '{"type":"ed25519","exportable":false,"allow_plaintext_backup":false}' || true)
  if printf '%s' "$created" | grep -q '"errors"' && ! printf '%s' "$created" | grep -q 'existing key'; then
    printf 'could not create %s: %s\n' "$name" "$created" >&2
    exit 1
  fi
  read_back=$(api GET "/v1/$MOUNT/keys/$name")
  type=$(printf '%s' "$read_back" | sed -n 's/.*"type":"\([^"]*\)".*/\1/p')
  if [ "$type" != "ed25519" ]; then
    printf '%s already exists with type %s; bundle format 1.0 admits only Ed25519\n' "$name" "$type" >&2
    exit 1
  fi
  # The *pinned* version, not the latest: a reference without one would silently change signer at
  # the operator's next rotation, and ADR-004 G.1 makes rotation additive precisely so that
  # history is never re-signed.
  version=$(printf '%s' "$read_back" | sed -n 's/.*"latest_version":\([0-9]*\).*/\1/p')
  echo "$variable=vault://$MOUNT/$name#v${version:-1}"
done

echo "#"
echo "# Rotating: 'vault write -f $MOUNT/keys/$PREFIX-<role>/rotate' creates a new version and"
echo "# changes nothing until you also move the '#v' in the reference above. That is the point:"
echo "# already-signed evidence keeps verifying under the version that signed it, and the exported"
echo "# keyset carries both. Never re-sign a corpus -- a re-signed corpus is byte-indistinguishable"
echo "# from a forged one (ADR-004 G.1)."
