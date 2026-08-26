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

case "${1:-up}" in
down)
  [ -f "$STATE_DIR/control-plane.pid" ] && kill "$(cat "$STATE_DIR/control-plane.pid")" 2>/dev/null || true
  rm -f "$STATE_DIR/control-plane.pid"
  "${compose[@]}" down --volumes --remove-orphans
  echo "demo stopped and its volume removed"
  exit 0
  ;;
esac

mkdir -p "$STATE_DIR" "$KEY_DIR"
"${compose[@]}" up -d --wait postgres-demo

# The application connects as mizan_app, never as the owner; RLS depends on it.
"${compose[@]}" exec -T postgres-demo psql -q -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  -c "ALTER ROLE mizan_app LOGIN PASSWORD 'demo-only-mizan'"

uv run mizan-dev-token --key-dir "$KEY_DIR" --print-public-key > "$STATE_DIR/identity.pub"

if [ -f "$STATE_DIR/control-plane.pid" ] && kill -0 "$(cat "$STATE_DIR/control-plane.pid")" 2>/dev/null; then
  kill "$(cat "$STATE_DIR/control-plane.pid")"
  sleep 1
fi

MIZAN_DATABASE_URL="$APP_DSN" \
MIZAN_JWT_ISSUER="urn:mizan:development:dev-token" \
MIZAN_JWT_AUDIENCE="mizan-control-plane" \
MIZAN_JWT_PUBLIC_KEY="$(cat "$STATE_DIR/identity.pub")" \
MIZAN_EVIDENCE_OBJECT_STORE_ROOT="$STATE_DIR/evidence" \
MIZAN_HTTP_PORT="$PORT" \
  uv run mizan-control-plane --log-level warning > "$STATE_DIR/control-plane.log" 2>&1 &
echo $! > "$STATE_DIR/control-plane.pid"

ready=""
for _ in $(seq 1 60); do
  if ! kill -0 "$(cat "$STATE_DIR/control-plane.pid")" 2>/dev/null; then
    echo "control plane exited during startup:" >&2
    cat "$STATE_DIR/control-plane.log" >&2
    exit 1
  fi
  # Readiness must come from Mizan, not from whatever else happens to hold the port.
  if curl -fsS "http://127.0.0.1:$PORT/health/ready" 2>/dev/null | grep -q '"evidence_verifier"'; then
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

uv run python scripts/seed_demo.py \
  --api-url "http://127.0.0.1:$PORT" --owner-database-url "$OWNER_DSN" --key-dir "$KEY_DIR"

echo
echo "GET /health/ready ->"
curl -fsS -w "\nHTTP %{http_code}\n" "http://127.0.0.1:$PORT/health/ready"
echo
echo "The wealth advisor calls three tools:"
uv run python scripts/demo_walk.py --api-url "http://127.0.0.1:$PORT" --key-dir "$KEY_DIR"
cat <<INFO

Control plane:  http://127.0.0.1:$PORT   (log: $STATE_DIR/control-plane.log)
Agent token:    uv run mizan-dev-token --key-dir $KEY_DIR --identity-kind agent \\
                  --auth-strength federated --subject prn_demo-customer --roles ''
Approver token: uv run mizan-dev-token --key-dir $KEY_DIR --subject prn_ops-manager --roles manager
Stop with:      make demo-down
INFO
