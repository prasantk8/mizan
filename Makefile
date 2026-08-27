.PHONY: check validate-baseline validate-ui-contract test-postgres demo demo-down benchmark-policy benchmark-sequencer benchmark-chain

check: validate-baseline validate-ui-contract

validate-baseline:
	python3 scripts/validate_baseline.py

validate-ui-contract:
	uv run python scripts/validate_ui_contract.py

test-postgres:
	bash scripts/test_postgres_schema.sh

demo:
	bash scripts/demo.sh up

demo-down:
	bash scripts/demo.sh down

benchmark-policy:
	uv run python -m benchmarks.policy_engine

benchmark-sequencer:
	uv run python -m benchmarks.evidence_sequencer

benchmark-chain:
	uv run python -m benchmarks.chain_verifier
