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

## Implementation Amendment E — registry write authority *(pending ratification: B-17)*

**Date:** 2026-08-27 · **Trigger:** Stage 5 acceleration review, T-077a · **Spec anchors:** SPEC v1.3 §3 `/v1/agents`, `/v1/tools`, `/v1/policies`, V-22

`POST /v1/agents`, `POST /v1/tools`, `POST /v1/tools/{id}/binding-profile` and `POST /v1/policies`
authenticated the *tenant* and nothing else. Demonstrated on `474efce` against a running control
plane: a token with `identity_kind: "agent"` posted a `financial_write` tool and received 201. An
agent that can write to the registry can widen its own permissions without a policy change, an
approval, or anything a reviewer would see as an authorization event — the registry is what every
later decision is measured against.

The write authority is therefore narrower than the read authority:

- **Human, MFA or hardware, always.** `identity_kind` must be `human` and `auth_strength` must be
  `mfa` or `hardware`. Agent and service identities are refused with 403
  `registry_write_auth_insufficient`, as are password-strength humans.
- **Four eyes for a production HIGH/CRITICAL object**, on creation as well as on PATCH, using the
  same `X-Mizan-Second-Approval` header and the same distinctness rules as Amendment C. The object
  is protected if its own document declares production HIGH/CRITICAL *or* the deployment is
  running in production and the object is HIGH/CRITICAL.
- **Policy creation takes one operator.** A new policy enters `DRAFT` and is inert; reaching
  `ACTIVE` already requires a recorded simulation and an approver who is not the author (V-1), so
  the two-person control is at the point where the policy starts deciding, not where it is typed.

The rule has one home, `require_registry_authority`, and each repository entry point takes the
acting principal explicitly so a future route cannot omit it. Ratification is open as B-17: the
alternative the founder may prefer is a dedicated `registry.admin` service identity for
infrastructure-as-code, which this default deliberately refuses.

## Implementation Amendment D — the shipped listener publishes the verified peer

**Date:** 2026-08-26 · **Trigger:** Stage 5 acceleration review, T-066 · **Spec anchors:** SPEC v1.3 §8 `MIZAN_TLS_*`, I-23, `docs/deployment/mtls.md`

Amendment B requires the ASGI server adapter to expose the verified connection's `SSLObject` as
`scope["ssl_object"]`. No shipped ASGI server does: uvicorn builds its HTTP scope without it, so
`VerifiedPeerSpiffeMiddleware` read nothing behind a real listener and every execution endpoint
answered 401 regardless of the client certificate presented. Until T-066 there was no entrypoint
to notice this, because there was no entrypoint at all.

`mizan-control-plane` therefore installs a protocol class that publishes the transport's
`ssl_object` into each HTTP scope before dispatch. Nothing else about the contract changes:
identity still comes only from the verified TLS peer, headers are still never trusted, and the
middleware still requires `CERT_REQUIRED` and exactly one `spiffe://` URI SAN.

Production refuses to boot without `MIZAN_TLS_CERTIFICATE_FILE`, `MIZAN_TLS_PRIVATE_KEY_FILE`, and
`MIZAN_TLS_CLIENT_CA_FILE`. A production control plane that cannot authenticate an executor cannot
bind execution to one, and silently answering 401 to every execution call is a worse failure than
refusing to start.

## Implementation Amendment C — dual control is evaluated over both sides of a PATCH

**Date:** 2026-08-26 · **Trigger:** Stage 5 acceleration review, T-077b · **Spec anchors:** SPEC v1.3 §3 `PATCH /v1/agents/{agent_id}`, V-22

The original amendment named "production HIGH/CRITICAL agent changes" without saying which
document decides. The implementation read the **submitted** document, so the single write that
downgrades a production `CRITICAL` agent to `LOW` — while also changing its tools, parent, or
lifecycle state — evaluated as unprotected and needed no second approver. Protection could be
removed by the act it was meant to gate.

Dual control is therefore required when the **stored** document or the **submitted** document is a
production `HIGH`/`CRITICAL` agent. The union is the only reading under which the control is not
self-defeating; nothing else about the amendment changes.

The same write also re-enforces the delegation edge `create_agent` checks: whenever a PATCH moves
`parent_agent_id`, the named parent must list the child in `delegation.allowed_agent_ids`, and the
`agent_delegations` edge is moved with it. Previously a PATCH could graft an agent onto any parent
in the tenant, and the edge table silently kept the stale row.

## Implementation Amendment B — application-terminated workload mTLS

**Date:** 2026-08-25 · **Trigger:** R-004 F-5 · **Spec anchors:** SPEC v1.3.1 §3, I-23, V-17

v1 terminates workload mTLS in the application process. The listener requires a client certificate
against the deployment trust bundle and exposes the verified connection `SSLObject` to ASGI.
`VerifiedPeerSpiffeMiddleware` extracts exactly one `spiffe://` URI SAN and populates
`client_cert_spiffe`; missing, malformed, SAN-less, or ambiguous certificates remain 401. CN and
subject DN are never identity sources.

Trusted proxy headers are explicitly absent. Adding proxy termination later requires a new threat
analysis proving the authenticated proxy-to-application hop and header stripping rules. Certificate
issuance and rotation remain outside T-020; the normative listener/trust-bundle requirements are in
`docs/deployment/mtls.md`.

## Implementation Amendment F — outage-free identity verification-key rotation

**Date:** 2026-08-31 · **Trigger:** two-product pilot T-122 · **Spec anchors:** SPEC v1.3 §8 `MIZAN_IDENTITY_JWKS`, V-24

The single `MIZAN_JWT_PUBLIC_KEY` made rotation a choice between rejecting tokens from the new
issuer key or replacing the PEM and immediately rejecting every still-live token from the old key.
Identity verification now consumes one deployment-pinned, public-only JWKS document. Every token
must carry `kid`; that identifier selects exactly one configured key, and its JOSE `alg` must equal
the key's explicit allowlisted algorithm. Symmetric keys, private parameters, duplicate identifiers,
missing identifiers and unknown or retired identifiers are refused. Token metadata never supplies a
URL, a key, or any other trust root, and validation performs no request-time network call.

Rotation is additive and uses the existing bounded token lifetime as its clock:

1. deploy the old and new public JWKs to every control-plane replica;
2. only after all replicas accept both `kid` values, switch the IdP to the new signing key;
3. wait at least `MIZAN_IDENTITY_TOKEN_MAX_TTL_SECONDS` after the old key stopped issuing tokens;
4. deploy the new-only JWKS. A token naming the removed `kid` is then refused even if freshly signed.

This overlap does not delay emergency revocation after suspected compromise: the operator removes
the key immediately and accepts that its outstanding bearer tokens stop working. Remote JWKS
discovery, refresh cadence and multi-issuer tenancy remain separate trust-policy decisions and are
not introduced by T-122. The executable procedure is
`docs/deployment/identity-key-rotation.md` and CI runs the same three-stage drill.
