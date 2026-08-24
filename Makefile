.PHONY: check validate-baseline test-postgres

check: validate-baseline

validate-baseline:
	python3 scripts/validate_baseline.py

test-postgres:
	bash scripts/test_postgres_schema.sh

