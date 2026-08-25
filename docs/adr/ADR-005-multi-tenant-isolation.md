# ADR-005: Multi-Tenant Data Isolation Strategy

**Status:** ACCEPTED (T-001 ratified in all required roles)
**Deciders:** Product/Architecture Lead, Cybersecurity Architect
**Date:** 2026-08-25
**Spec anchors:** SPEC_v1 §0 rule 6, §3 (tenant from token), Invariant I-3; PRD §71, §72, §41

## Context

PRD §71 requires per-tenant isolation of agents, policies, tools, customers, audit records, encryption keys, and configuration; enterprise deployments additionally need single-tenant, customer-managed keys, private networking, and customer-controlled data planes. PRD §72 adds data-residency policy enforcement (e.g., UAE-region-only). A cross-tenant leak in a *security control plane sold to banks* is an existential product failure — this is the highest-consequence ADR.

Key forces:

- Same logical platform across SaaS, private cloud, on-prem (PRD §41) — the isolation model must be deployment-model-independent.
- Policy evaluation caches (Redis) and Kafka topics are as leak-prone as the database.
- Hash chains are per-tenant (ADR-004), which aligns naturally with tenant-partitioned storage.
- Cost: schema-per-tenant or DB-per-tenant multiplies migration and ops burden at SaaS scale.

## Options Considered

1. **Shared Postgres, shared schema + mandatory `tenant_id` column + PostgreSQL Row-Level Security (RLS), with per-tenant crypto and namespacing in Redis/Kafka; DB-per-tenant reserved for enterprise tier.**
2. **Schema-per-tenant.** Better blast-radius, painful at 100+ tenants (migrations, connection pooling), still one DB credential domain.
3. **Database/cluster-per-tenant for everyone.** Maximal isolation; operationally and economically wrong for SaaS entry tier, correct for enterprise/on-prem.

## Decision (proposed)

Adopt **Option 1 as the SaaS baseline with Option 3 as the enterprise tier** — one codebase, two deployment profiles:

- **Postgres:** every table carries `tenant_id`; **RLS enabled and FORCED on every tenant-scoped table**; the application connects with a role that cannot bypass RLS; `SET app.tenant_id` is derived **only** from the validated token (SPEC I-3). No query may add `WHERE tenant_id=` manually as the primary control — RLS is the control, app filters are hygiene.
- **Defense in depth:** repository layer additionally asserts result tenancy (belt-and-braces against RLS misconfig); CI runs a cross-tenant leak test suite (fuzzed IDs across tenants must always 404, never 403-with-existence-leak).
- **Redis:** key prefix `t:{tenant_id}:…` enforced by a wrapper client that refuses un-prefixed keys; separate logical DBs per environment; policy-cache entries carry tenant + policy version in the key.
- **Kafka:** shared topics with `tenant_id` partition key at entry tier; per-tenant topic prefixes (`{tenant}.mizan.*`) at enterprise tier; consumers ACL-scoped.
- **Encryption:** envelope encryption with a per-tenant DEK; DEKs wrapped by tenant KEK in KMS/HSM. Enterprise tier: customer-managed KEK (BYOK) — key revocation renders the tenant's data cryptographically shredded.
- **Residency (PRD §72):** tenants pin to a region cell at creation; cells share nothing but the control-plane image registry. Residency policies (e.g., "no external model") are ordinary Mizan policies evaluated like any other — residency enforcement eats its own dog food.
- **Tenant lifecycle:** offboarding = export (records + anchors + verifier) then DEK destruction; `tnt_` IDs are never reused.

## Consequences

- (+) One isolation model, three deployment models; enterprise tier is a *stricter profile*, not a fork.
- (+) RLS + token-derived tenancy makes I-3 enforceable at the database, not just in code review.
- (−) RLS adds planner overhead (~small, must be included in the 50 ms budget benchmarks) and demands discipline: any table missed by RLS is a hole — CI must diff `pg_policies` against the schema on every migration.
- (−) Per-tenant DEKs complicate the hash-chain anchor format (anchors sign ciphertext or plaintext hashes? decision: hashes are computed over plaintext canonical JSON pre-encryption, so verification requires decryption rights — acceptable, verification is tenant-performed).
- (~) Noisy-neighbor risk at SaaS tier handled via per-tenant rate limits (429 by tier, see ADR-003 load shedding).

## Compliance Mapping

| Framework | Mapping |
|---|---|
| NIST AI RMF | GOVERN 1.7 / MAP 4.x (third-party & data governance boundaries) |
| ISO/IEC 42001 | A.7.4 (data management), A.2/A.3 (organizational boundaries) |
| ISO 27001 (adjacent) | A.8.3 information segregation; cryptographic controls A.10 |
| Data residency | Region cells + policy-enforced residency support UAE/GCC hosting requirements without legal claims (PRD §72–73) |
| OWASP Agentic AI | Limits blast radius of #8 MCP/server compromise and #11 data exfiltration to one tenant |

## Open Questions

- [ ] Region cell topology for pilot (single UAE cell?) and cell failover story.
- [ ] BYOK ceremony details for enterprise tier (who can rotate, break-glass).
- [ ] Do approval UIs ever need cross-tenant views for MSP/partner operators? (Current stance: no; partners get per-tenant identities.)

## Amendment A — machine-enforced typed identifier contract (T-021)

The I-16 contract is now enforced at the frozen-SPEC boundary, not left to code review. Every JSON
Schema property ending in `_id` must resolve through `common#/$defs/*Id`, and every `_ids` property
must be an array whose items resolve that way. Foreign and workload identifiers remain semantically
distinct types: `SessionId`, `DeviceId`, and `SpiffeId` deliberately have no Mizan prefix, while
registry identifiers retain their disjoint prefixes. This prevents a structurally valid value from
crossing identifier domains merely because both domains happened to use JSON strings.

The same blocking gate also checks Draft 2020-12 meta-schema validity, behavioural-token
reachability (or a dated waiver), and producibility of every policy decision path under the closed
ADR_Record schema. Committed negative fixtures are executed by the gate so CI proves each control
can reject its named defect class.
