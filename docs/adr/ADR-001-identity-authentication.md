# ADR-001: Identity & Authentication Strategy (Zero-Trust Machine-to-Machine)

**Status:** ACCEPTED (T-001 ratified in all required roles)
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC_v1 §2.1 (`Agent.identity`), §3 (auth conventions), Invariant I-3

## Context

Every Mizan caller is a machine: agents authorizing actions, gateways redeeming execution tokens, services registering tools. The PRD (§14, §30) requires OAuth 2.0/OIDC, JWT, mTLS, and workload identity support, with zero-trust posture (no network-location trust, no long-lived shared secrets). Agents must be first-class identities distinct from the humans they act for (principal ≠ agent — the delegation chain carries both). Mizan must never become the primary secrets store (PRD §30, §56).

Key forces:

- Banking customers run heterogeneous IdPs (Azure AD/Entra, Ping, ForgeRock, Keycloak) — Mizan must federate, not replace (Principle 9).
- Authorization decisions bind to `(tenant, agent, principal, delegation_chain)`; token claims are the only trusted carrier of these.
- p95 < 50 ms on `/v1/authorize` leaves no room for per-request remote token introspection.
- Kubernetes-native deployment (PRD §47) makes SPIFFE/SPIRE-style workload identity natural for service-to-service mTLS.

## Options Considered

1. **OAuth2 client-credentials JWTs per agent, federated to customer IdP; mTLS (SPIFFE SVID) for infra-level service identity.** Local JWKS validation, short TTL (≤ 5 min), DPoP or mTLS-bound tokens.
2. **Pure mTLS everywhere** (cert = identity). Simple trust model, but poor claim expressiveness (delegation chain, principal, tenant) and painful rotation at agent granularity.
3. **API keys + HMAC.** Fast to build; fails zero-trust review (long-lived bearer secrets), rejected for anything beyond local dev.

## Decision (proposed)

Adopt **Option 1 — layered identity**:

- **Transport layer:** mTLS between all Mizan components and from gateways/sidecars, with SPIFFE IDs as workload identity.
- **Application layer:** every API call carries a short-lived JWT access token from the tenant's IdP (client-credentials for agents; OIDC for humans in the approval UI). `tenant_id`, `agent_id` are claims; Mizan validates locally against cached JWKS.
- **Delegation:** agent-to-agent calls use OAuth token exchange (RFC 8693) so the child's token carries `act` (actor) chains matching `delegation_chain` — no ambient inheritance (Invariant I-4/I-5).
- **Sender constraint:** production tokens must be mTLS-bound (RFC 8705) or DPoP; plain bearer allowed only in `development`.
- **Execution capabilities:** an authorization-service capability is not interchangeable with the caller's IdP access token. It has fixed audience `mizan-execution-gateway` and binds `tenant_id`, `agent_id`, `principal_id`, `delegation_chain_hash`, and `authorized_executor` (the peer SPIFFE ID). Redeem, heartbeat, and completion compare the authenticated peer identity to that claim. Issuer, algorithms, and verification keyset are deployment allowlists; token-carried metadata never selects a trust root (SPEC I-23/V-17).
- **Approvers:** human votes require OIDC sessions with `auth_strength ∈ {mfa, hardware}` (SPEC §5.2 G2).
- Credentials/keys live in the customer vault (HashiCorp Vault / cloud KMS); Mizan stores only `credential_ref`.

## Consequences

- (+) Claim-rich tokens make the EvaluationContext verifiable rather than asserted.
- (+) Token-exchange delegation gives cryptographic backing to the delegation-chain invariants.
- (−) Requires per-tenant IdP federation setup during onboarding — must be productized in the pilot playbook.
- (−) Local JWKS caching introduces a revocation lag window (mitigate: ≤5 min TTL + suspension check inside the policy engine, which is authoritative regardless of token validity).
- (~) SPIRE adds operational surface; acceptable for K8s-native targets, revisit for on-prem VM deployments.

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | GOVERN 1.2 / MAP 3.4 (accountable identities for AI actors); MANAGE 2.4 |
| ISO/IEC 42001 | A.4.2 resources & A.7 (roles, accountability for AI systems) |
| OWASP Agentic AI | Mitigates threat families #4 identity abuse, #5 agent impersonation, #10 unauthorized delegation (PRD §17) |
| Zero Trust (NIST SP 800-207) | Per-request verification, no implicit trust zones |
| Banking expectations | mTLS + MFA for approvers aligns with GCC regulator guidance on privileged operations |

## Open Questions

- [ ] Minimum viable IdP matrix for pilot (Entra ID + Keycloak?)
- [ ] DPoP vs mTLS-bound tokens as the default sender-constraint mechanism?
- [ ] Do we mint a Mizan-internal token after IdP validation (token normalization) or pass through?

**Resolved for execution capabilities:** Mizan mints a distinct internal capability after authorization. The open question applies only to ordinary control-plane access-token normalization; an external IdP token is never itself an execution capability.

## Implementation Amendment — Registry dual control

Production HIGH/CRITICAL agent changes authenticate two distinct human principals with the same
allowlisted asymmetric IdP verifier. The primary principal uses the ordinary Authorization bearer;
the second uses `X-Mizan-Second-Approval: Bearer …`. Both tokens must carry MFA or hardware strength,
the same tenant, and different principal IDs. A caller-supplied name is never evidence of approval,
and bearer values are neither persisted nor included in events.
