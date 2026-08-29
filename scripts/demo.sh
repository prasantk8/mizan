#!/usr/bin/env bash
# `make demo` — a control plane you can talk to, from a clean checkout.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${MIZAN_DEMO_PORT:-8787}"
KEY_DIR="${MIZAN_DEMO_KEY_DIR:-var/demo-keys}"
STATE_DIR="var/demo"
OWNER_DSN="postgresql://mizan_owner:demo-only-mizan@127.0.0.1:55432/mizan"
APP_DSN="postgresql://mizan_app:demo-only-mizan@127.0.0.1:55432/mizan"
compose=(docker compose -f compose.yaml --profile demo -p mizan-demo)

TLS_DIR="$STATE_DIR/tls"
EVIDENCE_DIR="$STATE_DIR/evidence"
BUNDLE_DIR="$STATE_DIR/bundle"
# The stream the demo agent writes to. `mizan-export-evidence` takes one stream, and shard 0 is
# where a single-agent demo lands.
DEMO_STREAM="tnt_demo-bank:adr:0"

# Every background process this script starts, so `down` can stop all of them rather than
# leaving a drainer running against a database that has been deleted.
PIDS=(control-plane drain attest)

case "${1:-up}" in
down)
  for name in "${PIDS[@]}"; do
    [ -f "$STATE_DIR/$name.pid" ] && kill "$(cat "$STATE_DIR/$name.pid")" 2>/dev/null || true
    rm -f "$STATE_DIR/$name.pid"
  done
  "${compose[@]}" down --volumes --remove-orphans
  # The object store must go with the database. They are one evidence plane: a wiped database
  # beside a surviving store means the next run recomputes an anchor whose object already exists,
  # and `put_once` correctly refuses it as an immutable collision -- which is exactly how the
  # anchor cadence was found crashing the drain worker.
  rm -rf "$EVIDENCE_DIR" "$BUNDLE_DIR" "$STATE_DIR/keyset.json"
  echo "demo stopped; its volume and evidence store removed"
  exit 0
  ;;
esac

mkdir -p "$STATE_DIR" "$KEY_DIR"
"${compose[@]}" up -d --wait postgres-demo

# The application connects as mizan_app, never as the owner; RLS depends on it.
"${compose[@]}" exec -T postgres-demo psql -q -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  -c "ALTER ROLE mizan_app LOGIN PASSWORD 'demo-only-mizan'"

uv run mizan-dev-token --key-dir "$KEY_DIR" --print-public-key > "$STATE_DIR/identity.pub"

# ADR-001 Amendment B requires a verified peer SPIFFE identity on every execution endpoint, so
# without mutual TLS `/v1/actions/{id}/execute` answers 401 and the demo cannot reach the half of
# the product that matters. Development-only keys, from the generator the closed-loop integration
# test has used against a real listener since T-067.
uv run python scripts/dev_pki.py --directory "$TLS_DIR" \
  --executor-spiffe "spiffe://mizan-demo/executor/wealth" > /dev/null

for name in "${PIDS[@]}"; do
  if [ -f "$STATE_DIR/$name.pid" ] && kill -0 "$(cat "$STATE_DIR/$name.pid")" 2>/dev/null; then
    kill "$(cat "$STATE_DIR/$name.pid")"
  fi
done
sleep 1

# Shared by the control plane and by both workers: they sign with the same development keys and
# read the same object store, exactly as the production manifests give all three the same block.
runtime_environment=(
  "MIZAN_DATABASE_URL=$APP_DSN"
  "MIZAN_JWT_ISSUER=urn:mizan:development:dev-token"
  "MIZAN_JWT_AUDIENCE=mizan-control-plane"
  "MIZAN_JWT_PUBLIC_KEY=$(cat "$STATE_DIR/identity.pub")"
  "MIZAN_EVIDENCE_OBJECT_STORE_ROOT=$EVIDENCE_DIR"
)

env "${runtime_environment[@]}" \
  MIZAN_HTTP_PORT="$PORT" \
  MIZAN_TLS_CERTIFICATE_FILE="$TLS_DIR/server.pem" \
  MIZAN_TLS_PRIVATE_KEY_FILE="$TLS_DIR/server.key" \
  MIZAN_TLS_CLIENT_CA_FILE="$TLS_DIR/ca.pem" \
  uv run mizan-control-plane --log-level "${MIZAN_DEMO_LOG_LEVEL:-info}" \
    > "$STATE_DIR/control-plane.log" 2>&1 &
echo $! > "$STATE_DIR/control-plane.pid"

ready=""
for _ in $(seq 1 60); do
  if ! kill -0 "$(cat "$STATE_DIR/control-plane.pid")" 2>/dev/null; then
    echo "control plane exited during startup:" >&2
    cat "$STATE_DIR/control-plane.log" >&2
    exit 1
  fi
  # Readiness must come from Mizan, not from whatever else happens to hold the port.
  if curl -fsS --cacert "$TLS_DIR/ca.pem" --cert "$TLS_DIR/client.pem" \
      --key "$TLS_DIR/client.key" "https://127.0.0.1:$PORT/health/ready" 2>/dev/null \
      | grep -q '"evidence_verifier"'; then
    ready="yes"
    break
  fi
  sleep 0.5
done
if [ -z "$ready" ]; then
  echo "no Mizan control plane answered /health/ready on port $PORT" >&2
  cat "$STATE_DIR/control-plane.log" >&2
  exit 1
fi

API_URL="https://127.0.0.1:$PORT"
# A listener with a client CA configured demands a certificate on every connection, so even
# /health/ready needs one. That is the contract ADR-001 Amendment B asks for, not an
# inconvenience to work around.
curl_mtls=(curl -fsS --cacert "$TLS_DIR/ca.pem" --cert "$TLS_DIR/client.pem" --key "$TLS_DIR/client.key")

# The two workloads the production manifests run, started here for the same reason: without the
# drainer no evidence receipt is ever written and every financial write is refused 403
# `immutable_receipt_missing` (T-099); without the attestation runner every anchor stays pending
# (T-106). A demo that omits them is a demo of a Mizan that cannot execute a payment.
env "${runtime_environment[@]}" MIZAN_DRAIN_TENANTS="tnt_demo-bank" \
  uv run mizan-drain-outbox --interval-seconds 0.5 > "$STATE_DIR/drain.log" 2>&1 &
echo $! > "$STATE_DIR/drain.pid"

uv run python scripts/seed_demo.py \
  --api-url "$API_URL" --owner-database-url "$OWNER_DSN" --key-dir "$KEY_DIR" \
  --tls-dir "$TLS_DIR"

echo
echo "GET /health/ready ->"
"${curl_mtls[@]}" -w "\nHTTP %{http_code}\n" "$API_URL/health/ready"
echo
uv run python scripts/demo_walk.py --api-url "$API_URL" --key-dir "$KEY_DIR" --tls-dir "$TLS_DIR"

# The evidence the run just produced, exported and then checked by the standalone verifier --
# which imports no Mizan module and is the artifact an auditor would actually be handed.
echo
echo "Exporting the evidence and verifying it offline:"
rm -rf "$BUNDLE_DIR"
# The published keyset is a tenant-scoped read, so it needs an identity like any other route.
auditor_token="$(uv run mizan-dev-token --key-dir "$KEY_DIR" --subject prn_ops-manager --roles manager)"
# /v1/audit/keys answers {"items": [...]}; the exporter takes the bare array that a holder
# would have been given, so unwrap it here rather than teaching the exporter about the envelope.
"${curl_mtls[@]}" -H "Authorization: Bearer $auditor_token" "$API_URL/v1/audit/keys" \
  | uv run python -c 'import json,sys; json.dump(json.load(sys.stdin)["items"], sys.stdout)' \
  > "$STATE_DIR/keyset.json"
# The demo signs with development custody, and T-065 made that a refusal rather than a warning:
# a bundle whose private keys are sha256(key_id) is forgeable by anyone who reads it, so the
# exporter will not produce one unless a human names the reason. The flag is the demo's answer,
# and the bundle carries it -- the verifier prints it back below.
uv run mizan-export-evidence \
  --database-url "$APP_DSN" --object-store "$EVIDENCE_DIR" --keyset "$STATE_DIR/keyset.json" \
  --tenant-id tnt_demo-bank --stream-id "$DEMO_STREAM" --output "$BUNDLE_DIR" \
  --allow-development-custody "make demo: local development keys, not evidence"
uv run python scripts/verify_evidence_export.py "$BUNDLE_DIR"
cat <<INFO

Control plane:  $API_URL   (log: $STATE_DIR/control-plane.log)
                mutual TLS; trust root $TLS_DIR/ca.pem, executor cert $TLS_DIR/client.pem
Drain worker:   log: $STATE_DIR/drain.log   (without it every financial write is refused)
Evidence:       $EVIDENCE_DIR   bundle: $BUNDLE_DIR
Agent token:    uv run mizan-dev-token --key-dir $KEY_DIR --identity-kind agent \\
                  --auth-strength federated --subject prn_demo-customer --roles ''
Approver token: uv run mizan-dev-token --key-dir $KEY_DIR --subject prn_ops-manager --roles manager
Stop with:      make demo-down
INFO
