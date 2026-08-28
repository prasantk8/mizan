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

"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  -c "ALTER ROLE mizan_app LOGIN PASSWORD 'integration-only-mizan'"
published_port="$("${compose[@]}" port postgres 5432 | awk -F: '{print $NF}')"
MIZAN_TEST_DATABASE_URL="postgresql://mizan_app:integration-only-mizan@127.0.0.1:${published_port}/mizan" \
  uv run pytest -q tests/unit \
    tests/integration/test_evidence_export_postgres.py tests/integration/test_authorize_postgres.py \
    --cov=mizan_control_plane.execution --cov-report=json:.coverage-execution.json
uv run python scripts/validate_execution_coverage.py
MIZAN_TEST_DATABASE_URL="postgresql://mizan_app:integration-only-mizan@127.0.0.1:${published_port}/mizan" \
  make benchmark-sequencer

"${compose[@]}" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  < infra/postgres/rollback/0001_domain_schema.sql
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  -c "DO \$\$ BEGIN
        IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='mizan')
           OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mizan_app') THEN
          RAISE EXCEPTION 'rollback contract failed';
        END IF;
      END \$\$;"
