.PHONY: check validate-baseline test-postgres benchmark-policy

check: validate-baseline

validate-baseline:
	python3 scripts/validate_baseline.py

test-postgres:
	bash scripts/test_postgres_schema.sh

benchmark-policy:
	uv run python -m benchmarks.policy_engine
