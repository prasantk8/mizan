# Explicit implementation waivers

This ledger is machine-read by `scripts/validate_baseline.py`. A waiver must name the exact
SPEC behavioural token, an ISO date, and a bounded disposition; deleting the implementation without
adding a reviewed row fails CI.

| Token | Date | Disposition |
|---|---|---|
| `NOT_IMPLEMENTED` | 2026-08-25 | T-016 will implement ratified B-10 Option A immediately after the T-021 drift gate lands. |
| `system_fail_closed` | 2026-08-25 | T-017 will implement the existing I-8/V-15 evidence path during Stage 2. |
