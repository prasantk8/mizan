# Mizan Operator UI

Dependency-free, same-origin operator console served by FastAPI at `/`. It consumes the
tenant-scoped `/v1/decisions`, `/v1/audit`, and `/v1/audit/verify` contracts. Paste a short-lived
operator bearer token into the connection panel; the token remains in session storage only.

Run the control plane and open `http://localhost:8000/`. All enforcement remains server-side.
