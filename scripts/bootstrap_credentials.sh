#!/usr/bin/env bash
# Assemble customer-issued production credentials without printing or generating trust roots.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/bootstrap_credentials.sh --output DIR \
  --server-cert FILE --server-key FILE --client-ca FILE --server-ca FILE \
  --health-client-cert FILE --health-client-key FILE --tsa-root FILE \
  --vault-ca FILE --vault-token-file FILE

The script generates only PostgreSQL passwords. Certificates, trust roots and the Vault token
must come from customer-controlled issuers. Existing output is refused unless --force is supplied.
EOF
}

output=""
force=false
server_cert=""
server_key=""
client_ca=""
server_ca=""
health_client_cert=""
health_client_key=""
tsa_root=""
vault_ca=""
vault_token_file=""
while (($#)); do
  case "$1" in
    --output) output="${2:?missing value}"; shift 2 ;;
    --server-cert) server_cert="${2:?missing value}"; shift 2 ;;
    --server-key) server_key="${2:?missing value}"; shift 2 ;;
    --client-ca) client_ca="${2:?missing value}"; shift 2 ;;
    --server-ca) server_ca="${2:?missing value}"; shift 2 ;;
    --health-client-cert) health_client_cert="${2:?missing value}"; shift 2 ;;
    --health-client-key) health_client_key="${2:?missing value}"; shift 2 ;;
    --tsa-root) tsa_root="${2:?missing value}"; shift 2 ;;
    --vault-ca) vault_ca="${2:?missing value}"; shift 2 ;;
    --vault-token-file) vault_token_file="${2:?missing value}"; shift 2 ;;
    --force) force=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 64 ;;
  esac
done

[[ -n "$output" ]] || { usage >&2; exit 64; }
for specification in \
  "server-cert:$server_cert" "server-key:$server_key" "client-ca:$client_ca" \
  "server-ca:$server_ca" "health-client-cert:$health_client_cert" \
  "health-client-key:$health_client_key" "tsa-root:$tsa_root" "vault-ca:$vault_ca" \
  "vault-token-file:$vault_token_file"
do
  name="${specification%%:*}"
  path="${specification#*:}"
  [[ -f "$path" ]] || { printf '%s must name a readable file\n' "--$name" >&2; exit 66; }
done
if [[ -e "$output" && "$force" != true ]]; then
  printf '%s already exists; inspect it or rerun with --force\n' "$output" >&2
  exit 73
fi

for certificate in "$server_cert" "$health_client_cert" "$client_ca" "$server_ca" "$tsa_root" "$vault_ca"; do
  openssl x509 -in "$certificate" -noout >/dev/null
done
openssl pkey -in "$server_key" -noout >/dev/null
openssl pkey -in "$health_client_key" -noout >/dev/null
cmp -s \
  <(openssl x509 -in "$server_cert" -pubkey -noout) \
  <(openssl pkey -in "$server_key" -pubout) || {
    printf 'server certificate and private key do not match\n' >&2; exit 65;
  }
cmp -s \
  <(openssl x509 -in "$health_client_cert" -pubkey -noout) \
  <(openssl pkey -in "$health_client_key" -pubout) || {
    printf 'health-client certificate and private key do not match\n' >&2; exit 65;
  }

umask 077
mkdir -p "$output/tls" "$output/runtime"
install -m 0644 "$server_cert" "$output/tls/server.pem"
install -m 0600 "$server_key" "$output/tls/server-key.pem"
install -m 0644 "$client_ca" "$output/tls/client-ca.pem"
install -m 0644 "$server_ca" "$output/tls/server-ca.pem"
install -m 0644 "$health_client_cert" "$output/tls/health-client.pem"
install -m 0600 "$health_client_key" "$output/tls/health-client-key.pem"
install -m 0644 "$tsa_root" "$output/tls/tsa-root.pem"
install -m 0644 "$vault_ca" "$output/tls/vault-ca.pem"
install -m 0600 "$vault_token_file" "$output/runtime/vault-token"

owner_password=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
app_password=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
export MIZAN_BOOTSTRAP_OWNER_PASSWORD="$owner_password"
export MIZAN_BOOTSTRAP_APP_PASSWORD="$app_password"
export MIZAN_BOOTSTRAP_ENV_TEMPLATE="$(cd "$(dirname "$0")/.." && pwd)/.env.example"
export MIZAN_BOOTSTRAP_ENV_OUTPUT="$output/.env.production"
python3 - <<'PY'
import os
from pathlib import Path

template = Path(os.environ["MIZAN_BOOTSTRAP_ENV_TEMPLATE"]).read_text(encoding="utf-8")
template = template.replace("__GENERATED_OWNER_PASSWORD__", os.environ["MIZAN_BOOTSTRAP_OWNER_PASSWORD"])
template = template.replace("__GENERATED_APP_PASSWORD__", os.environ["MIZAN_BOOTSTRAP_APP_PASSWORD"])
Path(os.environ["MIZAN_BOOTSTRAP_ENV_OUTPUT"]).write_text(template, encoding="utf-8")
PY
chmod 0600 "$output/.env.production"
unset MIZAN_BOOTSTRAP_OWNER_PASSWORD MIZAN_BOOTSTRAP_APP_PASSWORD owner_password app_password

printf 'Production credential layout created at %s\n' "$output"
printf 'Next: edit %s/.env.production, provision Vault and Object Lock, then run the readiness command in INSTALL.md.\n' "$output"
