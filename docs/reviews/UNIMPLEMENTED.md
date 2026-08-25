# Explicit implementation waivers

This ledger is machine-read by `scripts/validate_baseline.py`. A waiver must name the exact
SPEC behavioural token, an ISO date, and a bounded disposition; deleting the implementation without
adding a reviewed row fails CI.

| Token | Date | Disposition |
|---|---|---|
| `system_fail_closed` | 2026-08-25 | T-017 will implement the existing I-8/V-15 evidence path during Stage 2. |
| `constraints_hash` | 2026-08-25 | Removed from v1 issuance by ratified B-10 Option A; constrained execution is deferred to T-028/v1.4. |
