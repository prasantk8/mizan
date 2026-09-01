# Mizan Operator UI

Dependency-free, same-origin operator console served by FastAPI at `/`. It consumes the
tenant-scoped `/v1/decisions`, `/v1/audit`, and `/v1/audit/verify` contracts. The operator
identity is established through the deployment's customer-IdP OIDC login. The browser
receives an opaque HttpOnly session cookie and never receives or stores the IdP token.

Run the control plane and open its configured HTTPS origin. All enforcement remains server-side;
HIGH/CRITICAL votes redirect through a fresh MFA/hardware step-up when required.
