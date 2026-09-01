.PHONY: check validate-baseline validate-ui-contract validate-ui-truth validate-vulnerability-allowlist test-postgres demo demo-down benchmark-policy benchmark-sequencer benchmark-chain

check: validate-baseline validate-ui-contract validate-ui-truth validate-vulnerability-allowlist

validate-baseline:
	uv run --frozen python scripts/validate_baseline.py

validate-ui-contract:
	uv run python scripts/validate_ui_contract.py

validate-ui-truth:
	node --test ui/tests/ui-truth.test.js

validate-vulnerability-allowlist:
	uv run python scripts/validate_vulnerability_allowlist.py

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
