#!/usr/bin/env bash
set -euo pipefail

project_name="mizan-schema-test"
compose=(docker compose -f compose.yaml -f compose.test.yaml -p "$project_name")
cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${compose[@]}" up -d --wait postgres
"${compose[@]}" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  < tests/integration/postgres/schema_contract.sql
