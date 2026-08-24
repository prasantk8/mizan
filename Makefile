.PHONY: check validate-baseline

check: validate-baseline

validate-baseline:
	python3 scripts/validate_baseline.py

