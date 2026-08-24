.PHONY: check validate-baseline test-postgres benchmark-policy benchmark-sequencer benchmark-chain

check: validate-baseline

validate-baseline:
	python3 scripts/validate_baseline.py

test-postgres:
	bash scripts/test_postgres_schema.sh

benchmark-policy:
	uv run python -m benchmarks.policy_engine

benchmark-sequencer:
	uv run python -m benchmarks.evidence_sequencer

benchmark-chain:
	uv run python -m benchmarks.chain_verifier
