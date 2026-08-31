#!/usr/bin/env bash
set -euo pipefail

project_name="mizan-schema-test"
compose=(docker compose -f compose.yaml -f compose.test.yaml -p "$project_name")
postgres_tests=(
  tests/integration/test_approval_expiry_postgres.py
  tests/integration/test_authorize_postgres.py
  tests/integration/test_closed_loop_postgres.py
  tests/integration/test_evidence_export_postgres.py
  tests/integration/test_mcp_gateway_postgres.py
  tests/integration/test_observability_postgres.py
  tests/integration/test_policy_studio_postgres.py
  tests/integration/test_sdk_postgres.py
  tests/integration/test_service_boot_postgres.py
)
cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Keep the task's nine-file inventory honest in both directions. A new
# *_postgres.py module must be added here, and removing/renaming one cannot
# silently leave a stale path that pytest never collects.
discovered_postgres_tests=(tests/integration/test_*_postgres.py)
if [[ "${discovered_postgres_tests[*]}" != "${postgres_tests[*]}" ]]; then
  echo "PostgreSQL contract inventory differs from tests/integration/test_*_postgres.py" >&2
  echo "declared:   ${postgres_tests[*]}" >&2
  echo "discovered: ${discovered_postgres_tests[*]}" >&2
  exit 1
fi

"${compose[@]}" up -d --wait postgres
"${compose[@]}" exec -T postgres \
  psql -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  < tests/integration/postgres/schema_contract.sql

"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U mizan_owner -d mizan \
  -c "ALTER ROLE mizan_app LOGIN PASSWORD 'integration-only-mizan'"
published_port="$("${compose[@]}" port postgres 5432 | awk -F: '{print $NF}')"
test_database_url="postgresql://mizan_app:integration-only-mizan@127.0.0.1:${published_port}/mizan"

# execution.py's debt gate needs unit and live-PostgreSQL coverage together.
# Run them separately so a skip in an unrelated integration suite cannot hide
# behind the database job's green status, then combine the coverage data.
uv run coverage erase
uv run pytest -q tests/unit \
  --cov=mizan_control_plane.execution --cov-report=
if ! postgres_output="$({
  MIZAN_TEST_DATABASE_URL="$test_database_url" \
    uv run pytest -q "${postgres_tests[@]}" \
      --cov=mizan_control_plane.execution --cov-append \
      --cov-report=json:.coverage-execution.json
} 2>&1)"; then
  printf '%s\n' "$postgres_output"
  exit 1
fi
printf '%s\n' "$postgres_output"
execution_confirmation="$(
  printf '%s\n' "$postgres_output" | uv run python scripts/validate_pytest_execution.py
)"
printf '%s\n' "$execution_confirmation"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### PostgreSQL integration contract\n\n'
    printf -- '- `%s`\n' "${postgres_tests[@]}"
    printf '\n%s\n' "$execution_confirmation"
  } >> "$GITHUB_STEP_SUMMARY"
fi
uv run python scripts/validate_execution_coverage.py
MIZAN_TEST_DATABASE_URL="$test_database_url" \
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
