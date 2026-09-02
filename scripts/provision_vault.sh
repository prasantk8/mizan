#!/usr/bin/env bash
# Create the four Ed25519 Transit keys Mizan signs with plus the HMAC key it commits with, and
# print the configuration to set.
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

# Four signing roles and one MAC role (ADR-004 G.1 as amended by B-30 / T-054). The fifth is a
# Transit key of type `hmac`, not `ed25519`: it authenticates the pre-redaction commitment on every
# audit record and has no public half. It is created here rather than left to an operator because a
# missing commitment key makes the control plane refuse to start, and because the one thing worse
# than forgetting it is creating it as an ed25519 key and having the audit trail quietly commit
# under an evidence signing key.
for triple in \
  "evidence-receipt:MIZAN_EVIDENCE_RECEIPT_KEY_REF:ed25519" \
  "evidence-anchor:MIZAN_EVIDENCE_ANCHOR_KEY_REF:ed25519" \
  "execution-token:MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF:ed25519" \
  "degraded-grant:MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF:ed25519" \
  "audit-commitment:MIZAN_AUDIT_HMAC_KEY_REF:hmac"
do
  role="${triple%%:*}"
  rest="${triple#*:}"
  variable="${rest%%:*}"
  want_type="${rest##*:}"
  name="$PREFIX-$role"
  # `exportable` and `allow_plaintext_backup` are left at their false defaults deliberately and
  # named here so that nobody adds them later thinking they are conveniences.
  # Transit requires an explicit `key_size` for an `hmac` key (32-512 bytes) and rejects the
  # field for `ed25519`, whose size is fixed by the curve. 32 bytes is 256 bits, matching the
  # digest HMAC-SHA256 produces; anything shorter weakens the commitment I-12 depends on.
  if [ "$want_type" = "hmac" ]; then
    body="{\"type\":\"hmac\",\"key_size\":32,\"exportable\":false,\"allow_plaintext_backup\":false}"
  else
    body="{\"type\":\"$want_type\",\"exportable\":false,\"allow_plaintext_backup\":false}"
  fi
  created=$(api POST "/v1/$MOUNT/keys/$name" "$body" || true)
  if printf '%s' "$created" | grep -q '"errors"' && ! printf '%s' "$created" | grep -q 'existing key'; then
    printf 'could not create %s: %s\n' "$name" "$created" >&2
    exit 1
  fi
  read_back=$(api GET "/v1/$MOUNT/keys/$name")
  type=$(printf '%s' "$read_back" | sed -n 's/.*"type":"\([^"]*\)".*/\1/p')
  if [ "$type" != "$want_type" ]; then
    if [ "$want_type" = "hmac" ]; then
      printf '%s already exists with type %s; the audit commitment key must be a separate hmac key (ADR-004 G.1)\n' "$name" "$type" >&2
    else
      printf '%s already exists with type %s; bundle format 1.0 admits only Ed25519\n' "$name" "$type" >&2
    fi
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
