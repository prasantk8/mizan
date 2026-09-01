# Mizan SPEC v1.3 — Strict Contract Baseline

**Status:** BASELINE CANDIDATE — content-frozen for T-001 human ratification; not authorized for product implementation until accepted
**Supersedes:** SPEC v1.2 (2026-08-25). v1.3 applies ratified review R-003: independently controlled rejection-review epochs, bounded transient tool arguments with genuine execution revalidation, and a stable semantic Policy hash across lifecycle transitions. Earlier findings remain recorded in [`docs/reviews/R-001-baseline-review-disposition.md`](docs/reviews/R-001-baseline-review-disposition.md), [`docs/reviews/R-002-baseline-review-disposition.md`](docs/reviews/R-002-baseline-review-disposition.md), and [`docs/reviews/R-003-completion-blocker-disposition.md`](docs/reviews/R-003-completion-blocker-disposition.md).
**Source of truth:** `mizan-prd-v1.md` (Product), this file (Engineering Contracts)
**Change control:** Any change to a schema, endpoint, event, state machine, invariant, or configuration key in this file requires (a) an ADR in `docs/adr/`, (b) a version bump of the affected object's `schema_version`, and (c) an entry in `WORK_LOG.md`. No agent (human or LLM) may drift from these contracts silently.

---

## 0. Scope & Zero-Drift Rules

This spec covers the **Mizan v0.1 Control Plane** (PRD §37, §83–95): Agent Registry, Tool Registry, Policy Engine, Authorization API, Human Approval, Action Decision Records, Audit.

Zero-drift rules for all implementing agents:

1. **Canonical schemas are closed.** All Mizan-owned JSON Schemas use `"additionalProperties": false`. New fields require a spec change, never an inline addition. Open JSON is confined to two named, size-limited boundaries: the inert external-payload envelope (§2.8), and transient `EvaluationContext.tool.arguments` used only to compute a binding hash. Tool arguments never become a policy namespace and are never persisted raw. A canonical schema is never fed a foreign payload directly.
2. **Enums are exhaustive.** Decision values are exactly: `ALLOW | DENY | REQUIRE_APPROVAL | CONSTRAIN | REDACT | ESCALATE`. v0.1 implements the first three; the rest MUST be accepted by parsers and rejected by the evaluator with `NOT_IMPLEMENTED`, never dropped.
3. **IDs are typed and opaque.** Every identifier field `$ref`s a named type in §2.0 (`common#/$defs/*`). Prefixes (`agt_`, `tool_`, `pol_`, `adr_`, `apr_`, `aud_`, `tnt_`, `prn_`, `lse_`, `epo_`) are **syntactic type tags, not authorization**: storage MUST additionally enforce typed foreign keys scoped by `(tenant_id, id)`. Never parse further meaning out of an ID.
4. **Every consequential path emits an event** from §4 and an ADR_Record from §2.3. A code path that executes a tool without both is a spec violation, not a TODO.
5. **Timestamps** are RFC 3339 UTC with millisecond precision. **Money** is `common#/$defs/Money` — `{ "amount": integer_minor_units, "currency": ISO-4217 }`, both required, never floats.
6. **Multi-tenancy is mandatory.** Every persisted object and every API call carries `tenant_id`. There is no "default tenant" code path.
7. **Input acceptance implies evidence representability.** If a request validates against `EvaluationContext` (§2.4), the resulting `ADR_Record` (§2.3) MUST be constructible without further enrichment or defaulting. Fields required in the evidence record are required in the input, or are supplied by a **mandatory registry-enrichment step that runs before evaluation and fails closed on miss** (§3.1, Invariant I-13). It is never acceptable to render a decision that cannot be recorded.
8. **Cross-field rules that JSON Schema cannot express live in §9** as numbered validation rules (V-n). They are contract, not implementation detail: a build that skips a V-rule is non-conforming.
9. **Behaviour that varies must be a named configuration key in §8** with a stated default, scope, and override authority. Magic numbers in code (TTLs, thresholds, quorum ceilings) are spec violations.

---

## 1. Canonical Enums

```text
DecisionType:      ALLOW | DENY | REQUIRE_APPROVAL | CONSTRAIN | REDACT | ESCALATE
RiskLevel:         LOW | MEDIUM | HIGH | CRITICAL
AgentLifecycle:    PROPOSED | ASSESSED | DESIGNED | SECURITY_REVIEW | APPROVED |
                   REGISTERED | ACTIVE | MONITORED | SUSPENDED | REVIEWED | RETIRED
PolicyLifecycle:   DRAFT | TESTED | APPROVED | ACTIVE | SUPERSEDED | RETIRED
ApprovalState:     PENDING | PARTIALLY_APPROVED | REVIEW_REQUIRED | APPROVED |
                   REJECTED | EXPIRED | ESCALATED | WITHDRAWN | OVERRIDDEN
EpochState:        OPEN | CLOSED_SUPERSEDED | CLOSED_TERMINAL
VoteType:          APPROVE | REJECT | ABSTAIN
RejectionMode:     veto | rejection_quorum | review_required
ExecutionState:    NOT_STARTED | LEASED | EXECUTING | EXECUTED | FAILED |
                   LEASE_EXPIRED | BLOCKED_FAIL_CLOSED
Environment:       development | staging | production
DataClass:         public | internal | confidential | pii | financial | secret
ActionType:        read | write | financial_read | financial_write | communicate |
                   export | delete | delegate
AuthMethod:        oauth2_client_credentials | oidc | jwt_svid | mtls | workload_identity
AuthStrength:      password | mfa | hardware | federated
DegradedReason:    risk_engine_down | policy_engine_down | policy_cache_down | store_down | none
```

---

## 2. Domain Models (JSON Schema, draft 2020-12)

`$ref: "common#/$defs/X"` resolves to `https://mizan.ai/schemas/common/1.2.json#/$defs/X`.

### 2.0 Common definitions (typed IDs, hashes, money)

Every identifier in every schema below references this file. A build that inlines `{"type":"string"}` for an ID is non-conforming (Invariant I-16).

```json
{
  "$id": "https://mizan.ai/schemas/common/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Mizan common definitions",
  "$defs": {
    "TenantId":    { "type": "string", "pattern": "^tnt_[a-z0-9-]{4,64}$" },
    "AgentId":     { "type": "string", "pattern": "^agt_[a-z0-9-]{6,64}$" },
    "ToolId":      { "type": "string", "pattern": "^tool_[a-z0-9_.-]{3,64}$" },
    "PolicyId":    { "type": "string", "pattern": "^pol_[a-z0-9-]{4,64}$" },
    "DecisionId":  { "type": "string", "pattern": "^adr_[a-z0-9-]{8,64}$" },
    "ApprovalId":  { "type": "string", "pattern": "^apr_[a-z0-9-]{8,64}$" },
    "EpochId":     { "type": "string", "pattern": "^epo_[a-z0-9-]{8,64}$" },
    "LeaseId":     { "type": "string", "pattern": "^lse_[a-z0-9-]{8,64}$" },
    "AuditId":     { "type": "string", "pattern": "^aud_[a-z0-9-]{8,64}$" },
    "DecisionEventId": { "type": "string", "pattern": "^dev_[a-z0-9-]{8,64}$" },
    "VoteId":      { "type": "string", "pattern": "^vot_[a-z0-9-]{8,64}$" },
    "BindingProfileId": { "type": "string", "pattern": "^bp_[a-z0-9_.-]{3,64}$" },
    "ProjectionId": { "type": "string", "pattern": "^prj_[a-z0-9_.-]{3,64}$" },
    "DegradedGrantId": { "type": "string", "pattern": "^dgr_[a-z0-9-]{8,64}$" },
    "RequestId":   { "type": "string", "format": "uuid", "description": "Client-generated idempotency key; UUIDv7 recommended." },
    "TraceId":     { "type": "string", "pattern": "^[0-9a-f]{32}$" },
    "SpanId":      { "type": "string", "pattern": "^[0-9a-f]{16}$" },
    "SpiffeId":    { "type": "string", "pattern": "^spiffe://[A-Za-z0-9._/-]{3,256}$" },
    "SessionId":   { "type": "string", "minLength": 1, "maxLength": 128 },
    "DeviceId":    { "type": "string", "minLength": 1, "maxLength": 128 },
    "ModelId":     { "type": "string", "minLength": 1, "maxLength": 128 },
    "CustomerId":  { "type": "string", "minLength": 1, "maxLength": 128, "description": "Tenant-scoped foreign customer identifier." },
    "DlpPolicyId": { "type": "string", "pattern": "^dlp_[a-z0-9_.-]{3,64}$" },
    "EvidenceStreamId": { "type": "string", "pattern": "^tnt_[a-z0-9-]{4,64}:(adr|audit):[a-z0-9-]{1,32}$" },
    "AdrStreamId": { "type": "string", "pattern": "^tnt_[a-z0-9-]{4,64}:adr:[a-z0-9-]{1,32}$" },
    "ActorSubjectId": { "type": "string", "minLength": 2, "maxLength": 128, "description": "Typed by the adjacent kind discriminator; storage validates the corresponding tenant-scoped registry when applicable." },
    "PrincipalId": { "type": "string", "pattern": "^prn_[a-zA-Z0-9-]{2,64}$" },

    "SystemId": {
      "type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
      "description": "Identifier of an owning system or service (e.g. core-banking, crm.emea)."
    },
    "PartyRef": {
      "type": "string", "minLength": 2, "maxLength": 128,
      "description": "Accountable human or service identity for governance sign-off. Resolvable in the tenant directory; not an ID with a Mizan prefix."
    },
    "ResourceId": {
      "type": "string", "pattern": "^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]{0,127}$",
      "description": "Foreign identifier. Not Mizan-issued, so no prefix tag. The typed key is (tenant_id, resource_owner, resource.type, id) — enforced in storage, never inferred from the string."
    },
    "RoleRef": {
      "type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
      "description": "Role identifier as issued by the tenant IdP and mirrored in the Mizan role registry."
    },
    "ControlDomain": {
      "type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{1,63}$",
      "description": "Independently administered authority group. Dual control counts distinct control domains, not distinct role labels (ADR-007)."
    },

    "Sha256Hex": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "HmacHex":   { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "Timestamp": { "type": "string", "format": "date-time" },
    "KeyRef": {
      "type": "string", "pattern": "^(kms|hsm|local)://[A-Za-z0-9._/-]{3,256}$",
      "description": "Pointer to key material. Never a key value."
    },
    "Money": {
      "type": "object", "additionalProperties": false,
      "required": ["amount", "currency"],
      "properties": {
        "amount":   { "type": "integer", "description": "Minor units. Never a float." },
        "currency": { "type": "string", "pattern": "^[A-Z]{3}$", "description": "ISO-4217" }
      }
    },
    "DelegationChain": {
      "type": "array", "minItems": 1, "maxItems": 6, "uniqueItems": true,
      "items": { "$ref": "common#/$defs/AgentId" },
      "description": "Ordered agent_ids, root first, acting agent last. Invariant I-4."
    },
    "JsonPointer": { "type": "string", "pattern": "^(/[^/~]*(~[01][^/~]*)*)*$" },
    "ConditionNode": {
      "description": "Policy condition tree (ADR-002). Recursive. Field paths are restricted to the evaluation namespace; foreign payload fields are unreachable except through mapped DTO paths (Invariant I-17).",
      "oneOf": [
        {
          "type": "object", "additionalProperties": false,
          "required": ["field", "op"],
          "properties": {
            "field": { "type": "string",
              "pattern": "^(principal|agent|customer|intent|tool|action|resource|business|security|environment|mapped)\\.[a-z0-9_.]{1,120}$" },
            "op":    { "enum": ["eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "present", "absent", "matches"] },
            "value": {}
          }
        },
        { "type": "object", "additionalProperties": false, "required": ["all"],
          "properties": { "all": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "$ref": "common#/$defs/ConditionNode" } } } },
        { "type": "object", "additionalProperties": false, "required": ["any"],
          "properties": { "any": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "$ref": "common#/$defs/ConditionNode" } } } },
        { "type": "object", "additionalProperties": false, "required": ["not"],
          "properties": { "not": { "$ref": "common#/$defs/ConditionNode" } } }
      ]
    }
  }
}
```

### 2.1 Agent

> **Rename from v1.0:** `resource_owner` → `accountable_owner`. In v1.0 the same field name meant "accountable human" on Agent and "owning system" on `resource`, which made the two indistinguishable in evidence. The names are now disjoint.

```json
{
  "$id": "https://mizan.ai/schemas/agent/1.1.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Agent",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "agent_id", "tenant_id", "name", "version",
               "owner", "accountable_owner", "purpose", "environment", "risk_tier",
               "lifecycle_state", "identity", "tools", "policies", "delegation",
               "created_at", "updated_at"],
  "properties": {
    "schema_version": { "const": "1.1" },
    "agent_id":  { "$ref": "common#/$defs/AgentId" },
    "tenant_id": { "$ref": "common#/$defs/TenantId" },
    "name":      { "type": "string", "minLength": 3, "maxLength": 120 },
    "version":   { "type": "string", "description": "SemVer of the agent build, e.g. 2.3.1" },
    "owner":     { "$ref": "common#/$defs/SystemId", "description": "Owning team/system, e.g. wealth-ai-team" },
    "accountable_owner": { "$ref": "common#/$defs/PartyRef", "description": "Named accountable individual or service identity for governance sign-off (PRD §48)" },
    "purpose":     { "type": "string", "maxLength": 500 },
    "environment": { "enum": ["development", "staging", "production"] },
    "model": {
      "type": "object", "additionalProperties": false,
      "required": ["provider", "model_id", "hosting"],
      "properties": {
        "provider": { "type": "string", "maxLength": 64 },
        "model_id": { "$ref": "common#/$defs/ModelId" },
        "hosting":  { "enum": ["internal", "external"] }
      }
    },
    "framework":       { "type": ["string", "null"], "maxLength": 64, "description": "Agent framework; informational, never trusted" },
    "risk_tier":       { "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
    "lifecycle_state": { "enum": ["PROPOSED", "ASSESSED", "DESIGNED", "SECURITY_REVIEW",
                                  "APPROVED", "REGISTERED", "ACTIVE", "MONITORED",
                                  "SUSPENDED", "REVIEWED", "RETIRED"] },
    "parent_agent_id": {
      "oneOf": [{ "$ref": "common#/$defs/AgentId" }, { "type": "null" }],
      "description": "Set when this agent was spawned/invoked by another agent. Root agents: null."
    },
    "identity": {
      "type": "object", "additionalProperties": false,
      "required": ["auth_method", "credential_ref"],
      "properties": {
        "auth_method":    { "enum": ["oauth2_client_credentials", "oidc", "jwt_svid", "mtls", "workload_identity"] },
        "credential_ref": { "$ref": "common#/$defs/KeyRef", "description": "Pointer into external vault (never a secret value)" },
        "spiffe_id":      { "oneOf": [{ "$ref": "common#/$defs/SpiffeId" }, { "type": "null" }] }
      }
    },
    "tools":    { "type": "array", "items": { "$ref": "common#/$defs/ToolId" },   "uniqueItems": true },
    "policies": { "type": "array", "items": { "$ref": "common#/$defs/PolicyId" }, "uniqueItems": true },
    "delegation": {
      "type": "object", "additionalProperties": false,
      "required": ["allowed_agent_ids", "max_delegation_depth", "inherit_parent_permissions"],
      "properties": {
        "allowed_agent_ids":    { "type": "array", "items": { "$ref": "common#/$defs/AgentId" }, "uniqueItems": true },
        "max_delegation_depth": { "type": "integer", "minimum": 0, "maximum": 5 },
        "inherit_parent_permissions": { "const": false,
          "description": "INVARIANT I-5: permission inheritance is structurally forbidden; a child's effective permissions are the intersection of its own grant and the delegation grant." }
      }
    },
    "behavioral_baseline_ref": { "type": ["string", "null"], "maxLength": 256 },
    "created_at": { "$ref": "common#/$defs/Timestamp" },
    "updated_at": { "$ref": "common#/$defs/Timestamp" },
    "metadata":   { "type": "object", "maxProperties": 32,
                    "additionalProperties": { "type": ["string", "number", "boolean", "null"] },
                    "description": "Operator annotations. NEVER an evaluation input — policy field paths cannot reach metadata (see ConditionNode)." }
  }
}
```

### 2.2 Policy

```json
{
  "$id": "https://mizan.ai/schemas/policy/1.3.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Policy",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "policy_id", "tenant_id", "name", "version",
               "status", "author", "applies_to", "conditions", "decision",
               "priority", "content_hash", "created_at"],
  "properties": {
    "schema_version": { "const": "1.3" },
    "policy_id": { "$ref": "common#/$defs/PolicyId" },
    "tenant_id": { "$ref": "common#/$defs/TenantId" },
    "name":      { "type": "string", "maxLength": 120 },
    "version":   { "type": "integer", "minimum": 1 },
    "previous_version": { "type": ["integer", "null"], "minimum": 1 },
    "status":    { "enum": ["DRAFT", "TESTED", "APPROVED", "ACTIVE", "SUPERSEDED", "RETIRED"] },
    "author":    { "$ref": "common#/$defs/PartyRef" },
    "approver":  { "oneOf": [{ "$ref": "common#/$defs/PartyRef" }, { "type": "null" }],
                   "description": "Enforced non-null and ≠ author once status ∈ {APPROVED, ACTIVE, SUPERSEDED} — see the if/then below and V-1." },
    "effective_from": { "oneOf": [{ "$ref": "common#/$defs/Timestamp" }, { "type": "null" }] },
    "applies_to": {
      "type": "object", "additionalProperties": false,
      "description": "All present selectors must match (AND). Absent selector = wildcard. An explicitly empty array matches nothing (V-6).",
      "properties": {
        "agent_ids":    { "type": "array", "items": { "$ref": "common#/$defs/AgentId" }, "uniqueItems": true },
        "tool_ids":     { "type": "array", "items": { "$ref": "common#/$defs/ToolId" },  "uniqueItems": true },
        "intents":      { "type": "array", "items": { "type": "string", "maxLength": 120 }, "uniqueItems": true },
        "action_types": { "type": "array", "items": { "enum": ["read", "write", "financial_read", "financial_write", "communicate", "export", "delete", "delegate"] }, "uniqueItems": true },
        "environments": { "type": "array", "items": { "enum": ["development", "staging", "production"] }, "uniqueItems": true },
        "risk_levels":  { "type": "array", "items": { "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }, "uniqueItems": true }
      }
    },
    "conditions": { "$ref": "common#/$defs/ConditionNode" },
    "decision":   { "enum": ["ALLOW", "DENY", "REQUIRE_APPROVAL", "CONSTRAIN", "REDACT", "ESCALATE"] },
    "constraints": {
      "type": ["object", "null"], "additionalProperties": false,
      "description": "Required iff decision ∈ {CONSTRAIN, REDACT}.",
      "properties": {
        "max_value":        { "oneOf": [{ "$ref": "common#/$defs/Money" }, { "type": "null" }] },
        "field_allowlist":  { "type": "array", "items": { "$ref": "common#/$defs/JsonPointer" }, "uniqueItems": true },
        "redact_pointers":  { "type": "array", "items": { "$ref": "common#/$defs/JsonPointer" }, "uniqueItems": true },
        "rate_limit_per_hour": { "type": ["integer", "null"], "minimum": 1 }
      }
    },
    "approval_requirements": {
      "type": ["object", "null"],
      "additionalProperties": false,
      "description": "Required iff decision = REQUIRE_APPROVAL. Drives the §5.2 state machine.",
      "required": ["quorum", "approver_roles", "expiry_seconds", "rejection_mode"],
      "properties": {
        "quorum":         { "type": "integer", "minimum": 1, "maximum": 5, "description": "M approvals needed (M-of-N). V-2 bounds it by eligible distinct control domains when dual control is on." },
        "approver_roles": { "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": { "$ref": "common#/$defs/RoleRef" } },
        "distinct_roles_required": { "type": "boolean", "default": false,
          "description": "Dual control. Counted APPROVE votes must come from distinct CONTROL DOMAINS (not merely distinct role labels) and distinct human identities — ADR-007." },
        "expiry_seconds": { "type": "integer", "minimum": 60, "maximum": 604800 },
        "escalation": {
          "type": ["object", "null"], "additionalProperties": false,
          "required": ["role", "trigger_fraction", "pool_mode", "carry_forward_votes", "reset_expiry"],
          "properties": {
            "role":               { "$ref": "common#/$defs/RoleRef" },
            "trigger_fraction":   { "type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1, "default": 0.5,
                                    "description": "Fraction of expiry_seconds after which escalation opens the next epoch." },
            "pool_mode":          { "enum": ["replace", "augment"],
                                    "description": "Whether the escalation role replaces the original approver pool or is added to it. No implicit default at runtime — V-3." },
            "carry_forward_votes": { "type": "boolean", "default": false,
                                     "description": "If true, APPROVE votes from the closed epoch count toward the new quorum only while the voter remains eligible under the new epoch's snapshot (I-15)." },
            "reset_expiry":       { "type": "boolean", "default": true,
                                    "description": "If true the new epoch gets a fresh expiry_seconds window; if false it inherits the original deadline." },
            "max_epochs":         { "type": "integer", "minimum": 1, "maximum": 5, "default": 2 }
          }
        },
        "rejection_mode":   { "enum": ["veto", "rejection_quorum", "review_required"], "default": "veto",
                              "description": "veto: any single REJECT is terminal. rejection_quorum: terminal at rejection_quorum_count REJECTs. review_required: first REJECT moves to REVIEW_REQUIRED for an independently controlled review workflow (ADR-007)." },
        "rejection_quorum_count": { "type": ["integer", "null"], "minimum": 1, "maximum": 5,
                                    "description": "Required iff rejection_mode = rejection_quorum (V-4)." },
        "review": {
          "type": ["object", "null"], "additionalProperties": false,
          "description": "Required iff rejection_mode=review_required. Opens a fresh independently controlled review epoch; prior votes never carry forward.",
          "required": ["approver_roles", "quorum", "expiry_seconds", "distinct_control_domains_required", "rejection_mode", "carry_forward_votes"],
          "properties": {
            "approver_roles": { "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true, "items": { "$ref": "common#/$defs/RoleRef" } },
            "quorum": { "type": "integer", "minimum": 1, "maximum": 5 },
            "expiry_seconds": { "type": "integer", "minimum": 60, "maximum": 604800 },
            "distinct_control_domains_required": { "const": true },
            "rejection_mode": { "enum": ["veto", "rejection_quorum"], "description": "review_required is forbidden here to prevent recursive review epochs." },
            "rejection_quorum_count": { "type": ["integer", "null"], "minimum": 1, "maximum": 5 },
            "carry_forward_votes": { "const": false }
          }
        },
        "override": {
          "type": ["object", "null"], "additionalProperties": false,
          "description": "Break-glass. Absent/null = no override is possible for this policy. Never silent, never unilateral by default.",
          "required": ["eligible_roles", "quorum", "justification_required"],
          "properties": {
            "eligible_roles":        { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "common#/$defs/RoleRef" } },
            "quorum":                { "type": "integer", "minimum": 1, "maximum": 5, "description": "Fresh quorum in a new epoch; prior votes never carry into an override epoch." },
            "justification_required": { "const": true },
            "distinct_control_domains_required": { "type": "boolean", "default": true },
            "notify":                { "type": "array", "items": { "enum": ["siem", "tenant_admin", "resource_owner", "compliance"] }, "uniqueItems": true, "default": ["siem", "compliance"] }
          }
        },
        "self_approval_allowed": { "const": false }
      }
    },
    "priority": { "type": "integer", "minimum": 0, "maximum": 1000,
                  "description": "Conflict resolution: higher wins; ties resolve to the most restrictive decision (DENY > REQUIRE_APPROVAL > CONSTRAIN/REDACT > ALLOW)" },
    "fail_open_allowed": { "type": "boolean", "default": false,
      "description": "Whether a matching context may take the degraded-allow path during a dependency outage. Permitted only when the evaluated risk floor is LOW and a signed, unexpired degraded grant exists (ADR-003, Invariant I-21). Default false everywhere, including on policy import." },
    "execution_token_ttl_seconds": { "type": ["integer", "null"], "minimum": 30, "maximum": 3600,
      "description": "Overrides the tool-level token TTL for contexts this policy governs. Governs time-to-START only; execution duration is governed by the lease (§2.11)." },
    "compiled_ref": { "type": ["string", "null"], "maxLength": 256, "description": "Content-addressed ref of compiled Cedar/Rego artifact" },
    "content_hash": { "$ref": "common#/$defs/Sha256Hex",
      "description": "SHA-256 of RFC 8785 canonical policy semantics excluding exactly content_hash, status, approver, and effective_from. Lifecycle transitions preserve it; every other content change requires a new version." },
    "created_at":  { "$ref": "common#/$defs/Timestamp" }
  },
  "allOf": [
    { "if":   { "properties": { "decision": { "const": "REQUIRE_APPROVAL" } }, "required": ["decision"] },
      "then": { "required": ["approval_requirements"],
                "properties": { "approval_requirements": { "type": "object" } } } },
    { "if":   { "properties": { "decision": { "enum": ["CONSTRAIN", "REDACT"] } }, "required": ["decision"] },
      "then": { "required": ["constraints"],
                "properties": { "constraints": { "type": "object" } } } },
    { "if":   { "properties": { "decision": { "not": { "enum": ["CONSTRAIN", "REDACT"] } } }, "required": ["decision"] },
      "then": { "not": { "required": ["constraints"] } } },
    { "if":   { "properties": { "status": { "enum": ["APPROVED", "ACTIVE", "SUPERSEDED"] } }, "required": ["status"] },
      "then": { "required": ["approver"],
                "properties": { "approver": { "type": "string" } } } },
    { "if":   { "properties": { "fail_open_allowed": { "const": true } }, "required": ["fail_open_allowed"] },
      "then": { "properties": { "decision": { "enum": ["ALLOW", "CONSTRAIN", "REDACT"] } } } },
    { "if":   { "properties": { "approval_requirements": { "properties": { "rejection_mode": { "const": "review_required" } }, "required": ["rejection_mode"] } }, "required": ["approval_requirements"] },
      "then": { "properties": { "approval_requirements": { "required": ["review"], "properties": { "review": { "type": "object" } } } } } }
  ]
}
```

### 2.3 ADR_Record (Action Decision Record)

The immutable authorization snapshot (PRD §13, §93). Written exactly once per authorization request; approval/execution updates append typed **DecisionEvents** (§2.12) referencing `decision_id` — the original is never mutated or cloned.

```json
{
  "$id": "https://mizan.ai/schemas/adr_record/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ADR_Record",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "decision_id", "tenant_id", "trace_id", "timestamp",
               "principal", "agent", "intent", "tool", "action", "resource",
               "context_hash", "risk", "policies", "decision", "decision_basis", "evaluator", "reasons",
               "approval", "execution", "degraded", "stream_id", "sequence_number",
               "prev_hash", "record_hash", "hash_alg"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "decision_id": { "$ref": "common#/$defs/DecisionId" },
    "tenant_id":   { "$ref": "common#/$defs/TenantId" },
    "trace_id":    { "$ref": "common#/$defs/TraceId", "description": "W3C traceparent trace-id (OpenTelemetry)" },
    "span_id":     { "oneOf": [{ "$ref": "common#/$defs/SpanId" }, { "type": "null" }] },
    "timestamp":   { "$ref": "common#/$defs/Timestamp" },
    "principal": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "type", "auth_strength"],
      "properties": {
        "id":   { "$ref": "common#/$defs/PrincipalId" },
        "type": { "enum": ["customer", "employee", "relationship_manager", "application", "service_identity"] },
        "role": { "oneOf": [{ "$ref": "common#/$defs/RoleRef" }, { "type": "null" }] },
        "auth_strength": { "enum": ["password", "mfa", "hardware", "federated"] }
      }
    },
    "agent": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "version", "delegation_chain"],
      "properties": {
        "id":              { "$ref": "common#/$defs/AgentId" },
        "version":         { "type": "string" },
        "parent_agent_id": { "oneOf": [{ "$ref": "common#/$defs/AgentId" }, { "type": "null" }] },
        "delegation_chain": { "$ref": "common#/$defs/DelegationChain" }
      }
    },
    "customer": { "type": ["object", "null"], "additionalProperties": false,
                  "required": ["id"],
                  "properties": { "id": { "$ref": "common#/$defs/CustomerId" },
                                  "segment": { "type": ["string", "null"], "maxLength": 64 } } },
    "intent": { "type": "string", "maxLength": 120 },
    "tool": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "parameters_hash", "binding_profile"],
      "properties": {
        "id":      { "$ref": "common#/$defs/ToolId" },
        "version": { "type": ["string", "null"] },
        "parameters_hash": { "$ref": "common#/$defs/Sha256Hex",
          "description": "SHA-256 over the canonicalized BINDING SUBSET of tool arguments (ADR-008), not the raw argument blob." },
        "binding_profile": {
          "type": "object", "additionalProperties": false,
          "required": ["profile_id", "profile_version"],
          "properties": {
            "profile_id":      { "$ref": "common#/$defs/BindingProfileId" },
            "profile_version": { "type": "integer", "minimum": 1 }
          }
        }
      }
    },
    "action": {
      "type": "object", "additionalProperties": false,
      "required": ["type"],
      "properties": {
        "type": { "enum": ["read", "write", "financial_read", "financial_write", "communicate", "export", "delete", "delegate"] },
        "estimated_value": { "oneOf": [{ "$ref": "common#/$defs/Money" }, { "type": "null" }] }
      }
    },
    "resource": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "type", "resource_owner", "data_classification"],
      "properties": {
        "id":   { "$ref": "common#/$defs/ResourceId" },
        "type": { "type": "string", "maxLength": 64, "examples": ["portfolio", "account", "payment", "customer_profile", "document"] },
        "resource_owner": { "$ref": "common#/$defs/SystemId", "description": "Owning system of the touched resource. Sourced from the tool/resource registry, not from the caller (V-7)." },
        "data_classification": { "enum": ["public", "internal", "confidential", "pii", "financial", "secret"] },
        "classification_source": { "enum": ["registry", "caller_asserted_upgrade"], "default": "registry",
          "description": "A caller may raise the classification above the registry value; it may never lower it (V-7)." }
      }
    },
    "context_hash": { "$ref": "common#/$defs/Sha256Hex",
      "description": "SHA-256 of the RFC 8785 canonical EvaluationContext excluding volatile paths (§8 volatile_context_paths). Re-checked before deferred execution (INVARIANT I-9)." },
    "risk": {
      "type": "object", "additionalProperties": false,
      "required": ["level", "floor_source"],
      "properties": {
        "level":   { "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
        "score":   { "type": ["number", "null"], "minimum": 0, "maximum": 100 },
        "factors": { "type": "array", "items": { "type": "string", "maxLength": 120 } },
        "floor_source": { "enum": ["risk_engine", "tool_registry_floor", "degraded_floor"],
          "description": "Which authority set the level. Under degradation the pre-evaluation tool floor applies (ADR-003)." }
      }
    },
    "policies": {
      "type": "array", "minItems": 0,
      "description": "Every policy that matched, with the exact version and hash evaluated. Empty only for default_deny or system_fail_closed (V-15).",
      "items": { "type": "object", "additionalProperties": false,
        "required": ["policy_id", "version", "content_hash"],
        "properties": { "policy_id": { "$ref": "common#/$defs/PolicyId" },
                        "version": { "type": "integer", "minimum": 1 },
                        "content_hash": { "$ref": "common#/$defs/Sha256Hex" } } }
    },
    "decision": { "enum": ["ALLOW", "DENY", "REQUIRE_APPROVAL", "CONSTRAIN", "REDACT", "ESCALATE"] },
    "decision_basis": { "enum": ["matched_policy", "default_deny", "system_fail_closed", "degraded_grant"],
      "description": "Why the evaluator was entitled to render the decision. default_deny and system_fail_closed make zero-policy DENYs evidence-representable; degraded_grant requires ADR_Record.degraded and a valid grant (V-15)." },
    "evaluator": {
      "type": "object", "additionalProperties": false,
      "required": ["build", "engine", "configuration_hash"],
      "properties": {
        "build": { "type": "string", "minLength": 1, "maxLength": 128 },
        "engine": { "type": "string", "minLength": 1, "maxLength": 64 },
        "configuration_hash": { "$ref": "common#/$defs/Sha256Hex", "description": "Pins deny-by-default and other evaluator behavior even when no policy matched." }
      }
    },
    "reasons":  { "type": "array", "minItems": 1, "items": { "type": "string", "maxLength": 240 } },
    "approval": {
      "type": "object", "additionalProperties": false,
      "required": ["required", "status"],
      "properties": {
        "required":    { "type": "boolean" },
        "approval_id": { "oneOf": [{ "$ref": "common#/$defs/ApprovalId" }, { "type": "null" }] },
        "status":      { "enum": ["NOT_REQUIRED", "PENDING", "PARTIALLY_APPROVED", "REVIEW_REQUIRED",
                                  "APPROVED", "REJECTED", "EXPIRED", "ESCALATED", "WITHDRAWN", "OVERRIDDEN"] },
        "quorum":      { "type": ["integer", "null"], "minimum": 1 },
        "deciding_epoch": { "oneOf": [{ "$ref": "common#/$defs/EpochId" }, { "type": "null" }],
                            "description": "The epoch whose votes satisfied (or terminated) the approval — I-15." },
        "votes": { "type": "array", "items": { "$ref": "https://mizan.ai/schemas/approval/1.2.json#/$defs/Vote" } }
      }
    },
    "execution": {
      "type": "object", "additionalProperties": false,
      "required": ["status"],
      "properties": {
        "status":      { "enum": ["NOT_STARTED", "LEASED", "EXECUTING", "EXECUTED", "FAILED", "LEASE_EXPIRED", "BLOCKED_FAIL_CLOSED"] },
        "lease_id":    { "oneOf": [{ "$ref": "common#/$defs/LeaseId" }, { "type": "null" }] },
        "result_hash": { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }] },
        "completed_at": { "oneOf": [{ "$ref": "common#/$defs/Timestamp" }, { "type": "null" }] }
      }
    },
    "degraded": {
      "type": "object", "additionalProperties": false,
      "required": ["is_degraded"],
      "properties": {
        "is_degraded":   { "type": "boolean", "description": "True whenever a required authorization dependency was unavailable, including a fail-closed DENY; it does not by itself mean the request was allowed." },
        "reason":        { "enum": ["risk_engine_down", "policy_engine_down", "policy_cache_down", "store_down", "none"], "default": "none" },
        "grant_ref":     { "type": ["string", "null"], "maxLength": 256, "description": "Signed degraded-mode grant under which this decision was taken (ADR-003)" },
        "buffered_at":   { "oneOf": [{ "$ref": "common#/$defs/Timestamp" }, { "type": "null" }] }
      }
    },
    "security_signals": { "type": "array", "items": { "type": "string", "maxLength": 120 } },
    "evaluation_latency_ms": { "type": ["number", "null"], "minimum": 0 },
    "stream_id": { "$ref": "common#/$defs/EvidenceStreamId",
      "description": "Chain stream this record belongs to: {tenant}:{kind}:{shard}. Chains and anchors are per stream_id (ADR-004)." },
    "sequence_number": { "type": "integer", "minimum": 0,
      "description": "Dense within stream_id. Allocated inside the committing transaction — an aborted write leaves no gap (I-20)." },
    "prev_hash":   { "$ref": "common#/$defs/Sha256Hex", "description": "record_hash of the previous record in this stream; genesis = 64 zero chars" },
    "record_hash": { "$ref": "common#/$defs/Sha256Hex", "description": "SHA-256 over RFC 8785 canonical record excluding record_hash itself (ADR-004)" },
    "hash_alg":    { "const": "SHA-256" },
    "canonicalization": { "const": "RFC8785" },
    "anchor_ref":  { "type": ["string", "null"], "maxLength": 256 },
    "immutable_receipt_ref": { "type": ["string", "null"], "maxLength": 256,
      "description": "Signed object-store publication receipt. Required before financial_write capability redemption (I-25/V-20)." }
  }
}
```

### 2.4 EvaluationContext

The full input to `POST /v1/authorize` (PRD §85–86). This is what gets canonicalized and hashed into `ADR_Record.context_hash`.

Fields that the evidence record requires are **required here or supplied by mandatory registry enrichment (§3.1)**. There is no third option (rule 7, Invariant I-13).

```json
{
  "$id": "https://mizan.ai/schemas/evaluation_context/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "EvaluationContext",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "request_id", "principal", "agent",
               "intent", "tool", "action", "resource", "environment", "timestamp"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "request_id": { "$ref": "common#/$defs/RequestId" },
    "tenant_id": { "oneOf": [{ "$ref": "common#/$defs/TenantId" }, { "type": "null" }],
      "description": "OPTIONAL AND ADVISORY. Tenancy is derived from the token (I-3). If present and mismatched, the request is rejected 403 — it is never used as the source." },
    "principal": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "type", "auth_strength"],
      "properties": {
        "id":   { "$ref": "common#/$defs/PrincipalId" },
        "type": { "enum": ["customer", "employee", "relationship_manager", "application", "service_identity"] },
        "role": { "oneOf": [{ "$ref": "common#/$defs/RoleRef" }, { "type": "null" }] },
        "auth_strength": { "enum": ["password", "mfa", "hardware", "federated"] }
      }
    },
    "agent": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "version", "delegation_chain"],
      "properties": {
        "id":      { "$ref": "common#/$defs/AgentId" },
        "version": { "type": "string" },
        "parent_agent_id":  { "oneOf": [{ "$ref": "common#/$defs/AgentId" }, { "type": "null" }] },
        "delegation_chain": { "$ref": "common#/$defs/DelegationChain",
          "description": "Root-first, acting agent last. A root agent sends a single-element chain — never an empty array or an omitted field." }
      }
    },
    "customer": { "type": ["object", "null"], "additionalProperties": false,
      "required": ["id"],
      "properties": { "id": { "$ref": "common#/$defs/CustomerId" }, "segment": { "type": ["string", "null"], "maxLength": 64 } } },
    "intent": { "type": "string", "maxLength": 120, "examples": ["portfolio_rebalance", "get_account_balance"] },
    "tool": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "arguments", "parameters_hash", "binding_profile"],
      "properties": {
        "id": { "$ref": "common#/$defs/ToolId" },
        "arguments": { "type": "object", "maxProperties": 256,
          "description": "Transient tool arguments. Maximum canonical size 65536 bytes, depth 16, 256 total keys, finite JSON numbers only. Used solely for binding-profile validation/hash computation; never persisted raw or exposed as a policy field." },
        "parameters_hash": { "$ref": "common#/$defs/Sha256Hex",
          "description": "SHA-256 over the canonicalized binding subset defined by the tool's parameter_binding_profile (§2.6, ADR-008). Volatile paths (nonces, timestamps, trace ids, presigned URLs, retry counters) are excluded by the profile so legitimate retries do not drift." },
        "binding_profile": {
          "type": "object", "additionalProperties": false,
          "required": ["profile_id", "profile_version"],
          "properties": {
            "profile_id":      { "$ref": "common#/$defs/BindingProfileId" },
            "profile_version": { "type": "integer", "minimum": 1 }
          }
        }
      }
    },
    "action": {
      "type": "object", "additionalProperties": false,
      "required": ["type"],
      "properties": { "type": { "enum": ["read", "write", "financial_read", "financial_write", "communicate", "export", "delete", "delegate"] } }
    },
    "resource": {
      "type": "object", "additionalProperties": false,
      "required": ["id", "type", "resource_owner", "data_classification"],
      "properties": {
        "id":   { "$ref": "common#/$defs/ResourceId" },
        "type": { "type": "string", "maxLength": 64 },
        "resource_owner": { "$ref": "common#/$defs/SystemId" },
        "data_classification": { "enum": ["public", "internal", "confidential", "pii", "financial", "secret"] }
      }
    },
    "business": { "type": ["object", "null"], "additionalProperties": false,
      "properties": {
        "transaction_value": { "oneOf": [{ "$ref": "common#/$defs/Money" }, { "type": "null" }] },
        "customer_consent":  { "type": ["boolean", "null"] },
        "risk_profile":      { "type": ["string", "null"], "maxLength": 64 },
        "channel":           { "type": ["string", "null"], "maxLength": 64 },
        "jurisdiction":      { "type": ["string", "null"], "pattern": "^[A-Z]{2}$", "examples": ["AE"] },
        "business_process":  { "type": ["string", "null"], "maxLength": 120 } } },
    "security": { "type": ["object", "null"], "additionalProperties": false,
      "properties": {
        "session_id":    { "oneOf": [{ "$ref": "common#/$defs/SessionId" }, { "type": "null" }] },
        "source_ip":     { "type": ["string", "null"], "maxLength": 45 },
        "device_id":     { "oneOf": [{ "$ref": "common#/$defs/DeviceId" }, { "type": "null" }] },
        "anomaly_score": { "type": ["number", "null"], "minimum": 0, "maximum": 1 },
        "prior_denials_in_session": { "type": ["integer", "null"], "minimum": 0 } } },
    "mapped": {
      "type": ["object", "null"], "additionalProperties": false,
      "description": "Allowlisted projection of external/MCP payload data (§2.8, ADR-006). The ONLY route by which foreign data reaches policy evaluation.",
      "properties": {
        "source":         { "$ref": "common#/$defs/SystemId" },
        "projection_id":  { "$ref": "common#/$defs/ProjectionId" },
        "projection_version": { "type": "integer", "minimum": 1 },
        "raw_envelope_hash":  { "$ref": "common#/$defs/Sha256Hex" },
        "fields": { "type": "object", "maxProperties": 64,
                    "additionalProperties": { "type": ["string", "number", "boolean", "null"] },
                    "description": "Scalars only. Nested structures must be flattened by the projection; unmapped fields are dropped with telemetry, never passed through." }
      }
    },
    "environment": { "enum": ["development", "staging", "production"] },
    "timestamp":   { "$ref": "common#/$defs/Timestamp" }
  }
}
```

### 2.4a ContextResponse (policy replay read model)

The tenant-scoped read model for replaying a recorded decision through policy simulation. `context`
is the normalized document committed beside the ADR_Record and hashed as `context_hash`. It is not a
reconstructed request: transient `tool.arguments` are intentionally absent and MUST NOT be added to
this response. A simulation client may supply an empty arguments object to the simulation request
envelope; arguments remain outside the policy namespace and the replay does not recompute binding.

```json
{
  "$id": "https://mizan.ai/schemas/context_response/1.0.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ContextResponse",
  "type": "object",
  "additionalProperties": false,
  "required": ["context_hash", "context"],
  "properties": {
    "context_hash": { "$ref": "common#/$defs/Sha256Hex" },
    "context": {
      "type": "object",
      "additionalProperties": false,
      "required": ["schema_version", "request_id", "principal", "agent", "intent", "tool",
                   "action", "resource", "environment", "timestamp"],
      "properties": {
        "schema_version": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/schema_version" },
        "request_id": { "$ref": "common#/$defs/RequestId" },
        "principal": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/principal" },
        "agent": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/agent" },
        "customer": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/customer" },
        "intent": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/intent" },
        "tool": {
          "type": "object",
          "additionalProperties": false,
          "required": ["id", "parameters_hash", "binding_profile"],
          "properties": {
            "id": { "$ref": "common#/$defs/ToolId" },
            "parameters_hash": { "$ref": "common#/$defs/Sha256Hex" },
            "binding_profile": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/tool/properties/binding_profile" }
          }
        },
        "action": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/action" },
        "resource": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/resource" },
        "business": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/business" },
        "security": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/security" },
        "mapped": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/mapped" },
        "environment": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/environment" },
        "timestamp": { "$ref": "https://mizan.ai/schemas/evaluation_context/1.2.json#/properties/timestamp" }
      }
    }
  }
}
```

### 2.5 AuditTrail

One entry per event (§4). ADR_Records are the *decision* evidence; AuditTrail is the *everything-else* ledger (registrations, policy changes, admin actions, security events). Both are hash-chained per stream (ADR-004).

> **Redaction evidence changed in v1.1.** v1.0's single `payload_hash` over pre-redaction content was both weak (an unsalted SHA-256 over low-entropy PII is dictionary-attackable) and unfalsifiable (it proved nothing about whether redaction *worked*). It is replaced by three artefacts: a plain hash of what is actually stored, a **keyed** commitment to the pre-redaction content, and a **redaction manifest with DLP attestation** (ADR-004 Amendment A, Invariants I-12, I-18, I-19).

```json
{
  "$id": "https://mizan.ai/schemas/audit_trail/1.1.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AuditTrail",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "audit_id", "tenant_id", "stream_id", "sequence_number",
               "event_type", "actor", "subject", "stored_payload_hash", "redaction",
               "timestamp", "prev_hash", "record_hash", "hash_alg", "canonicalization"],
  "properties": {
    "schema_version": { "const": "1.1" },
    "audit_id":  { "$ref": "common#/$defs/AuditId" },
    "tenant_id": { "$ref": "common#/$defs/TenantId" },
    "stream_id": { "$ref": "common#/$defs/EvidenceStreamId" },
    "sequence_number": { "type": "integer", "minimum": 0 },
    "event_type": { "type": "string", "pattern": "^mizan\\.[a-z_]+\\.[a-z_]+$" },
    "trace_id":   { "oneOf": [{ "$ref": "common#/$defs/TraceId" }, { "type": "null" }] },
    "actor": { "type": "object", "additionalProperties": false, "required": ["id", "kind"],
      "properties": { "id": { "$ref": "common#/$defs/ActorSubjectId" },
                      "kind": { "enum": ["human", "agent", "service", "system"] } } },
    "subject": { "type": "object", "additionalProperties": false, "required": ["id", "kind"],
      "properties": { "id": { "$ref": "common#/$defs/ActorSubjectId" },
                      "kind": { "enum": ["agent", "tool", "policy", "decision", "approval", "tenant", "config"] } } },
    "payload": { "type": ["object", "null"],
      "description": "Post-redaction event body as actually stored. MUST contain no field classified pii/secret (I-18)." },
    "stored_payload_hash": { "$ref": "common#/$defs/Sha256Hex",
      "description": "SHA-256 of the canonical STORED (post-redaction) payload. Verifiable by any auditor holding the record — this is what chain verification uses." },
    "source_commitment": {
      "type": ["object", "null"], "additionalProperties": false,
      "description": "Keyed commitment to the PRE-redaction payload. HMAC (not a bare hash) so low-entropy PII cannot be recovered by dictionary attack; verification requires the audit commitment key, held under separate authority.",
      "required": ["alg", "key_ref", "value"],
      "properties": {
        "alg":     { "const": "HMAC-SHA256" },
        "key_ref": { "$ref": "common#/$defs/KeyRef" },
        "value":   { "$ref": "common#/$defs/HmacHex" }
      }
    },
    "redaction": {
      "type": "object", "additionalProperties": false,
      "description": "Attestation of HOW this payload was redacted. Absent/incomplete attestation on a record whose payload could carry classified data is a write failure, not a warning (I-19).",
      "required": ["applied", "policy_id", "policy_version", "policy_hash", "redactor_build", "dlp"],
      "properties": {
        "applied":        { "type": "boolean" },
        "policy_id":      { "$ref": "common#/$defs/DlpPolicyId" },
        "policy_version": { "type": "integer", "minimum": 1 },
        "policy_hash":    { "$ref": "common#/$defs/Sha256Hex" },
        "input_schema_hash":  { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }] },
        "output_schema_hash": { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }] },
        "redactor_build": { "type": "string", "maxLength": 128, "description": "Build/version identity of the redactor that produced the stored payload" },
        "dlp": {
          "type": "object", "additionalProperties": false,
          "required": ["status", "findings_count", "scanner_version"],
          "properties": {
            "status":          { "enum": ["clean", "findings_redacted", "scan_failed", "not_applicable"] },
            "findings_count":  { "type": "integer", "minimum": 0 },
            "scanner_version": { "type": "string", "maxLength": 64 },
            "coverage_profile": { "type": ["string", "null"], "maxLength": 64,
                                  "description": "Classification-coverage profile applied. Hashing cannot prove an UNKNOWN sensitive field was recognised; coverage is evidenced by profile + regression corpus, not by cryptography." }
          }
        },
        "manifest": {
          "type": "array", "maxItems": 256,
          "description": "One entry per redacted field.",
          "items": {
            "type": "object", "additionalProperties": false,
            "required": ["pointer", "classification", "transformation", "commitment"],
            "properties": {
              "pointer":        { "$ref": "common#/$defs/JsonPointer" },
              "classification": { "enum": ["public", "internal", "confidential", "pii", "financial", "secret"] },
              "transformation": { "enum": ["drop", "mask", "tokenize", "hash", "generalize"] },
              "commitment":     { "$ref": "common#/$defs/HmacHex", "description": "HMAC of the original field value under the audit commitment key. Never a bare hash." }
            }
          }
        },
        "evidence_ref": { "type": ["string", "null"], "maxLength": 256,
          "description": "Optional encrypted original, retrievable only under legal hold, with its own short retention (§8 redaction_evidence_retention_days)." }
      }
    },
    "timestamp":   { "$ref": "common#/$defs/Timestamp" },
    "prev_hash":   { "$ref": "common#/$defs/Sha256Hex" },
    "record_hash": { "$ref": "common#/$defs/Sha256Hex" },
    "hash_alg":    { "const": "SHA-256" },
    "canonicalization": { "const": "RFC8785" },
    "anchor_ref":  { "type": ["string", "null"], "maxLength": 256, "description": "Signed checkpoint / WORM object covering this record's range (ADR-004)" },
    "retention_class": { "enum": ["standard", "regulatory_7y", "legal_hold"], "default": "regulatory_7y" },
    "exported_to": { "type": "array", "items": { "enum": ["kafka", "siem", "webhook", "object_store"] }, "uniqueItems": true }
  }
}
```

### 2.6 Tool

Promoted to a first-class schema in v1.1: the tool registry is now the authority for the pre-evaluation risk floor, the resource ownership/classification enrichment (rule 7), the parameter binding profile (ADR-008), and execution timing.

```json
{
  "$id": "https://mizan.ai/schemas/tool/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Tool",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "tool_id", "tenant_id", "name", "owner",
               "risk_tier", "action_type", "resource_owner", "data_classification",
               "binding_profile", "execution", "created_at"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "tool_id":   { "$ref": "common#/$defs/ToolId" },
    "tenant_id": { "$ref": "common#/$defs/TenantId" },
    "name":      { "type": "string", "maxLength": 120 },
    "owner":     { "$ref": "common#/$defs/SystemId" },
    "risk_tier": { "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
      "description": "Pre-evaluation risk FLOOR. Cheap and static so the ADR-003 degradation matrix is not circular." },
    "action_type": { "enum": ["read", "write", "financial_read", "financial_write", "communicate", "export", "delete", "delegate"] },
    "resource_owner": { "$ref": "common#/$defs/SystemId", "description": "Default owning system for resources this tool touches (registry enrichment source)" },
    "data_classification": { "enum": ["public", "internal", "confidential", "pii", "financial", "secret"],
      "description": "Default classification floor. Callers may raise, never lower (V-7)." },
    "permitted_agents": { "type": "array", "items": { "$ref": "common#/$defs/AgentId" }, "uniqueItems": true },
    "parameters_schema_ref": { "type": ["string", "null"], "maxLength": 256 },
    "binding_profile": {
      "type": "object", "additionalProperties": false,
      "description": "Defines WHICH arguments the execution token binds. Semantic, policy-relevant arguments only (ADR-008).",
      "required": ["profile_id", "profile_version", "canonicalization", "bound_pointers", "volatile_pointers"],
      "properties": {
        "profile_id":      { "$ref": "common#/$defs/BindingProfileId" },
        "profile_version": { "type": "integer", "minimum": 1 },
        "canonicalization": { "const": "RFC8785" },
        "bound_pointers":   { "type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": true,
                              "items": { "$ref": "common#/$defs/JsonPointer" },
                              "description": "Stable, semantically meaningful arguments (payee, amount, account, scope). These form parameters_hash." },
        "volatile_pointers": { "type": "array", "maxItems": 64, "uniqueItems": true,
                               "items": { "$ref": "common#/$defs/JsonPointer" },
                               "description": "Explicitly excluded: nonces, timestamps, trace/session ids, presigned URLs, retry counters, idempotency keys." },
        "unknown_pointer_policy": { "enum": ["reject", "ignore"], "default": "reject",
          "description": "What to do when the caller sends an argument covered by neither list. Default reject: an unclassified argument may be policy-relevant." }
      }
    },
    "execution": {
      "type": "object", "additionalProperties": false,
      "required": ["executor_spiffe_ids", "token_ttl_seconds", "lease_ttl_seconds", "heartbeat_interval_seconds", "max_lease_extensions"],
      "properties": {
        "executor_spiffe_ids": { "type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": true,
          "items": { "$ref": "common#/$defs/SpiffeId" },
          "description": "Registry-authorized workloads that may execute this tool. Capability issuance selects exactly one as authorized_executor (V-21)." },
        "token_ttl_seconds":  { "type": "integer", "minimum": 30, "maximum": 3600, "default": 300,
                                "description": "Time to START. Redeeming the token creates a lease; long jobs do not need a long-lived token." },
        "lease_ttl_seconds":  { "type": "integer", "minimum": 60, "maximum": 86400, "default": 900,
                                "description": "How long one execution lease survives without a heartbeat." },
        "heartbeat_interval_seconds": { "type": "integer", "minimum": 15, "maximum": 3600, "default": 60 },
        "max_lease_extensions": { "type": "integer", "minimum": 0, "maximum": 96, "default": 24 },
        "idempotency": { "enum": ["required", "optional", "none"], "default": "required",
                         "description": "Retries reuse the idempotency key, NOT a second authorization (ADR-008)." }
      }
    },
    "approval_requirements_ref": { "oneOf": [{ "$ref": "common#/$defs/PolicyId" }, { "type": "null" }] },
    "created_at": { "$ref": "common#/$defs/Timestamp" }
  }
}
```

### 2.7 Approval (with epochs)

An approval is a sequence of **epochs**. An epoch fixes the quorum, the eligibility snapshot, and the deadline; every vote binds to exactly one epoch. Escalation and override do not mutate an epoch — they close one and open the next (ADR-007, Invariant I-15).

```json
{
  "$id": "https://mizan.ai/schemas/approval/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Approval",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "approval_id", "tenant_id", "decision_id", "state",
               "current_epoch_id", "epochs", "created_at"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "approval_id": { "$ref": "common#/$defs/ApprovalId" },
    "tenant_id":   { "$ref": "common#/$defs/TenantId" },
    "decision_id": { "$ref": "common#/$defs/DecisionId" },
    "state": { "enum": ["PENDING", "PARTIALLY_APPROVED", "REVIEW_REQUIRED", "APPROVED",
                        "REJECTED", "EXPIRED", "ESCALATED", "WITHDRAWN", "OVERRIDDEN"] },
    "current_epoch_id": { "$ref": "common#/$defs/EpochId" },
    "epochs": {
      "type": "array", "minItems": 1, "maxItems": 5,
      "items": { "$ref": "#/$defs/Epoch" }
    },
    "context_hash_at_request": { "$ref": "common#/$defs/Sha256Hex" },
    "created_at": { "$ref": "common#/$defs/Timestamp" }
  },
  "$defs": {
    "Epoch": {
      "type": "object", "additionalProperties": false,
      "required": ["epoch_id", "epoch_number", "state", "opened_at", "expires_at",
                   "quorum", "rejection_mode", "eligibility", "votes", "kind"],
      "properties": {
        "epoch_id":     { "$ref": "common#/$defs/EpochId" },
        "epoch_number": { "type": "integer", "minimum": 1, "description": "Monotonic. Votes cite it; a vote citing a non-current number gets 409 (I-15)." },
        "kind":         { "enum": ["initial", "escalation", "override", "review"] },
        "state":        { "enum": ["OPEN", "CLOSED_SUPERSEDED", "CLOSED_TERMINAL"] },
        "opened_at":    { "$ref": "common#/$defs/Timestamp" },
        "expires_at":   { "$ref": "common#/$defs/Timestamp" },
        "closed_at":    { "oneOf": [{ "$ref": "common#/$defs/Timestamp" }, { "type": "null" }] },
        "quorum":       { "type": "integer", "minimum": 1, "maximum": 5 },
        "distinct_control_domains_required": { "type": "boolean", "default": false },
        "rejection_mode": { "enum": ["veto", "rejection_quorum", "review_required"] },
        "rejection_quorum_count": { "type": ["integer", "null"], "minimum": 1 },
        "eligibility": {
          "type": "object", "additionalProperties": false,
          "description": "IMMUTABLE snapshot taken when the epoch opened. Role claims presented at vote time are checked against this snapshot; a role granted after the epoch opened does not confer eligibility within it.",
          "required": ["snapshot_hash", "snapshot_at", "authority_source", "authority_mapping_version", "roles", "members"],
          "properties": {
            "snapshot_hash": { "$ref": "common#/$defs/Sha256Hex" },
            "snapshot_at":   { "$ref": "common#/$defs/Timestamp" },
            "authority_source": { "const": "mizan_role_registry", "description": "The Mizan tenant role registry is authoritative; IdP group claims are synchronized inputs, never interpreted directly at vote time." },
            "authority_mapping_version": { "type": "integer", "minimum": 1, "description": "Immutable reviewed mapping version used to assign roles and control domains." },
            "roles":   { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "common#/$defs/RoleRef" } },
            "members": {
              "type": "array", "maxItems": 512,
              "items": {
                "type": "object", "additionalProperties": false,
                "required": ["principal_id", "roles", "control_domain"],
                "properties": {
                  "principal_id":   { "$ref": "common#/$defs/PrincipalId" },
                  "roles":          { "type": "array", "minItems": 1, "uniqueItems": true, "items": { "$ref": "common#/$defs/RoleRef" } },
                  "control_domain": { "$ref": "common#/$defs/ControlDomain",
                    "description": "Exactly one per member per epoch. Resolves the multi-role case deterministically: the member's counted authority is their control domain, not whichever role label they submit." }
                }
              }
            }
          }
        },
        "carried_votes": {
          "type": "array", "maxItems": 5,
          "description": "Votes carried from a previous epoch under escalation.carry_forward_votes. Each retains its ORIGINAL epoch_id for evidence and is counted only while the voter remains in this epoch's eligibility snapshot.",
          "items": { "$ref": "#/$defs/Vote" }
        },
        "votes": { "type": "array", "maxItems": 64, "items": { "$ref": "#/$defs/Vote" } },
        "outcome": { "enum": ["PENDING", "QUORUM_MET", "REJECTED", "EXPIRED", "SUPERSEDED", "REVIEW_TRIGGERED", null], "default": "PENDING" }
      }
    },
    "Vote": {
      "type": "object", "additionalProperties": false,
      "required": ["vote_id", "epoch_id", "epoch_number", "approver_id", "approver_role",
                   "control_domain", "auth_strength", "vote", "timestamp"],
      "properties": {
        "vote_id":       { "$ref": "common#/$defs/VoteId" },
        "epoch_id":      { "$ref": "common#/$defs/EpochId" },
        "epoch_number":  { "type": "integer", "minimum": 1 },
        "approver_id":   { "$ref": "common#/$defs/PrincipalId" },
        "approver_role": { "$ref": "common#/$defs/RoleRef",
          "description": "Recorded from the ELIGIBILITY SNAPSHOT, not from client-supplied text. A submitted role is a request to vote under it, validated against the snapshot (G4)." },
        "control_domain": { "$ref": "common#/$defs/ControlDomain" },
        "auth_strength": { "enum": ["mfa", "hardware"], "description": "G2: password/federated-only identities cannot vote." },
        "vote":          { "enum": ["APPROVE", "REJECT", "ABSTAIN"] },
        "justification": { "type": ["string", "null"], "maxLength": 2000, "description": "Required for override epochs (V-5)." },
        "comment":       { "type": ["string", "null"], "maxLength": 2000 },
        "timestamp":     { "$ref": "common#/$defs/Timestamp" }
      }
    }
  }
}
```

### 2.8 ExternalPayloadEnvelope

The one place open content is permitted (rule 1, ADR-006). An envelope is inert data: it is stored, hashed, and telemetered, and it reaches evaluation only via a `mapped` projection (§2.4).

```json
{
  "$id": "https://mizan.ai/schemas/external_envelope/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ExternalPayloadEnvelope",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "tenant_id", "provider", "received_at", "raw_hash", "size_bytes",
               "content_type", "content_encoding", "payload", "persistence"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "tenant_id":  { "$ref": "common#/$defs/TenantId" },
    "provider":   { "$ref": "common#/$defs/SystemId" },
    "schema_uri":     { "type": ["string", "null"], "maxLength": 256 },
    "schema_version_declared": { "type": ["string", "null"], "maxLength": 64 },
    "received_at": { "$ref": "common#/$defs/Timestamp" },
    "raw_hash":    { "$ref": "common#/$defs/Sha256Hex" },
    "size_bytes":  { "type": "integer", "minimum": 0, "maximum": 1048576,
                     "description": "Server-computed byte count after transport decoding and before JSON parsing; must equal the measured payload size (V-18). Oversize → controlled tool error." },
    "content_type": { "const": "application/json" },
    "content_encoding": { "enum": ["identity", "gzip"], "description": "Compressed inputs are bounded by both compressed and decompressed limits before parsing (V-18)." },
    "payload":     {
                     "description": "THE ONLY open JSON value in this spec: object, array, scalar, or null. Transient capture only; never evaluated or persisted raw outside an encrypted evidence object." },
    "persistence": {
      "type": "object", "additionalProperties": false,
      "required": ["disposition", "redaction_attestation_ref"],
      "properties": {
        "disposition": { "enum": ["discarded_after_projection", "encrypted_evidence", "redacted_payload"],
          "description": "Raw payload is never written to searchable operational storage." },
        "redaction_attestation_ref": { "type": ["string", "null"], "maxLength": 256 },
        "encrypted_evidence_ref": { "type": ["string", "null"], "maxLength": 256 }
      }
    },
    "projection": {
      "type": ["object", "null"], "additionalProperties": false,
      "required": ["projection_id", "projection_version", "mapped_fields", "dropped_fields"],
      "properties": {
        "projection_id":      { "$ref": "common#/$defs/ProjectionId" },
        "projection_version": { "type": "integer", "minimum": 1 },
        "mapped_fields":  { "type": "array", "items": { "type": "string", "maxLength": 120 }, "uniqueItems": true },
        "dropped_fields": { "type": "array", "items": { "type": "string", "maxLength": 120 }, "uniqueItems": true,
                            "description": "Unknown/unmapped keys. Emitted as telemetry (mizan.integration.schema_drift) so provider evolution is visible without being trusted." }
      }
    }
  }
}
```

### 2.9 DegradedModeGrant

A degraded-allow path exists only under a signed, time-boxed, tenant-issued grant (ADR-003, Invariant I-21).

```json
{
  "$id": "https://mizan.ai/schemas/degraded_grant/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "DegradedModeGrant",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "grant_id", "tenant_id", "risk_ceiling", "allowed_components",
               "max_duration_seconds", "issued_at", "not_before", "expires_at", "issued_by",
               "signature_algorithm", "canonicalization", "signature", "key_ref", "nonce"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "grant_id":  { "$ref": "common#/$defs/DegradedGrantId" },
    "tenant_id": { "$ref": "common#/$defs/TenantId" },
    "risk_ceiling": { "const": "LOW", "description": "v0.1: degraded-allow is LOW-only. Raising this is a HUMAN-lane decision requiring an ADR." },
    "allowed_components": { "type": "array", "minItems": 1, "uniqueItems": true,
      "items": { "enum": ["risk_engine", "policy_cache", "record_store"] },
      "description": "Which unavailable dependencies this grant covers. The policy engine is never listed — its absence is always fail-closed." },
    "max_duration_seconds": { "type": "integer", "minimum": 60, "maximum": 86400, "default": 3600 },
    "issued_at":  { "$ref": "common#/$defs/Timestamp" },
    "not_before": { "$ref": "common#/$defs/Timestamp" },
    "expires_at": { "$ref": "common#/$defs/Timestamp" },
    "issued_by":  { "$ref": "common#/$defs/PartyRef" },
    "signature_algorithm": { "enum": ["EdDSA", "ES256"] },
    "canonicalization": { "const": "RFC8785" },
    "signature":  { "type": "string", "pattern": "^[A-Za-z0-9_-]{64,1024}$", "description": "Base64url signature over RFC 8785 canonical claims excluding signature." },
    "key_ref":    { "$ref": "common#/$defs/KeyRef", "description": "Must resolve in the tenant degraded-grant issuer trust registry; a caller-carried key is never trusted merely because it is named (V-16)." },
    "nonce":      { "type": "string", "pattern": "^dgn_[a-zA-Z0-9_-]{16,128}$", "description": "Single-use grant nonce. Replay after revocation or exhaustion is rejected (V-16)." }
  }
}
```

### 2.10 ExecutionToken (claims)

Issued on ALLOW and after approval. CONSTRAIN/REDACT/ESCALATE are refused with an auditable DENY
and HTTP 501 `NOT_IMPLEMENTED` in v1. Single-use, redeemed atomically for a lease.

```json
{
  "$id": "https://mizan.ai/schemas/execution_token/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ExecutionTokenClaims",
  "type": "object",
  "additionalProperties": false,
  "required": ["token_version", "jti", "iss", "aud", "tenant_id", "agent_id", "principal_id",
               "delegation_chain_hash", "authorized_executor", "decision_id", "tool_id",
               "parameters_hash", "binding_profile", "context_hash", "iat", "nbf", "exp"],
  "properties": {
    "token_version": { "const": "1.2" },
    "jti":        { "type": "string", "minLength": 16, "maxLength": 128, "description": "Single-use id; redemption CASes it to consumed (I-10)." },
    "iss":        { "type": "string", "minLength": 3, "maxLength": 256, "description": "Issuer allowlisted by deployment configuration; never accepted dynamically from the token." },
    "aud":        { "const": "mizan-execution-gateway" },
    "tenant_id":  { "$ref": "common#/$defs/TenantId" },
    "agent_id":   { "$ref": "common#/$defs/AgentId" },
    "principal_id": { "$ref": "common#/$defs/PrincipalId" },
    "delegation_chain_hash": { "$ref": "common#/$defs/Sha256Hex" },
    "authorized_executor": { "type": "string", "pattern": "^spiffe://[A-Za-z0-9._/-]{3,256}$",
      "description": "mTLS-authenticated workload identity permitted to redeem and operate the lease. Must match the peer SVID at redeem, heartbeat, and completion (V-17)." },
    "decision_id": { "$ref": "common#/$defs/DecisionId" },
    "tool_id":    { "$ref": "common#/$defs/ToolId" },
    "parameters_hash": { "$ref": "common#/$defs/Sha256Hex" },
    "binding_profile": {
      "type": "object", "additionalProperties": false,
      "required": ["profile_id", "profile_version"],
      "properties": { "profile_id": { "$ref": "common#/$defs/BindingProfileId" },
                      "profile_version": { "type": "integer", "minimum": 1 } }
    },
    "context_hash":   { "$ref": "common#/$defs/Sha256Hex" },
    "approval_epoch_id": { "oneOf": [{ "$ref": "common#/$defs/EpochId" }, { "type": "null" }],
                           "description": "Present when the decision required approval — binds the token to the epoch that actually granted it." },
    "iat": { "type": "integer", "minimum": 0, "description": "JWT NumericDate (seconds since Unix epoch)." },
    "nbf": { "type": "integer", "minimum": 0, "description": "JWT NumericDate; normally equal to iat." },
    "exp": { "type": "integer", "minimum": 0, "description": "JWT NumericDate = iat + tool/policy token_ttl_seconds (§8). Governs time-to-START only." }
  }
}
```

### 2.11 ExecutionLease

Created by redeeming a token. This is what survives a long-running job.

```json
{
  "$id": "https://mizan.ai/schemas/execution_lease/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ExecutionLease",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "lease_id", "redeemed_jti", "tenant_id", "agent_id", "principal_id",
               "authorized_executor", "decision_id", "tool_id",
               "state", "granted_at", "expires_at", "heartbeat_interval_seconds",
               "extensions_used", "max_extensions"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "lease_id":   { "$ref": "common#/$defs/LeaseId" },
    "redeemed_jti": { "type": "string", "minLength": 16, "maxLength": 128 },
    "tenant_id":  { "$ref": "common#/$defs/TenantId" },
    "agent_id":   { "$ref": "common#/$defs/AgentId" },
    "principal_id": { "$ref": "common#/$defs/PrincipalId" },
    "authorized_executor": { "type": "string", "pattern": "^spiffe://[A-Za-z0-9._/-]{3,256}$" },
    "decision_id": { "$ref": "common#/$defs/DecisionId" },
    "tool_id":    { "$ref": "common#/$defs/ToolId" },
    "state":      { "enum": ["LEASED", "EXECUTING", "EXECUTED", "FAILED", "LEASE_EXPIRED"] },
    "idempotency_key": { "type": ["string", "null"], "maxLength": 128,
      "description": "Retries of the SAME execution reuse this key against the lease. A retry is not a second authorization (ADR-008)." },
    "granted_at":  { "$ref": "common#/$defs/Timestamp" },
    "expires_at":  { "$ref": "common#/$defs/Timestamp" },
    "last_heartbeat_at": { "oneOf": [{ "$ref": "common#/$defs/Timestamp" }, { "type": "null" }] },
    "heartbeat_interval_seconds": { "type": "integer", "minimum": 15, "maximum": 3600 },
    "extensions_used": { "type": "integer", "minimum": 0 },
    "max_extensions":  { "type": "integer", "minimum": 0, "maximum": 96 },
    "result_hash": { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }] }
  }
}
```

### 2.12 DecisionEvent (immutable decision amendments)

`ADR_Record` is the immutable authorization snapshot. Every later change is a `DecisionEvent`; it is never represented by rewriting or cloning the original ADR_Record. Events are ordered per decision and also participate in the tenant evidence chain. The event payload is deliberately small and typed; full Approval and ExecutionLease objects remain separately queryable by their typed references.

```json
{
  "$id": "https://mizan.ai/schemas/decision_event/1.2.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "DecisionEvent",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "event_id", "tenant_id", "decision_id", "decision_sequence",
               "event_type", "actor", "occurred_at", "payload", "stream_id", "sequence_number",
               "prev_hash", "record_hash", "hash_alg", "canonicalization"],
  "properties": {
    "schema_version": { "const": "1.2" },
    "event_id":   { "$ref": "common#/$defs/DecisionEventId" },
    "tenant_id":  { "$ref": "common#/$defs/TenantId" },
    "decision_id": { "$ref": "common#/$defs/DecisionId" },
    "decision_sequence": { "type": "integer", "minimum": 1, "description": "Dense, monotonic ordering within decision_id; allocated transactionally with the event insert (V-19)." },
    "previous_event_hash": { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }] },
    "event_type": { "enum": ["APPROVAL_EPOCH_OPENED", "APPROVAL_VOTE_CAST", "APPROVAL_RESOLVED",
                                    "CAPABILITY_ISSUED", "LEASE_STARTED", "LEASE_EXTENDED",
                                    "EXECUTION_COMPLETED", "EXECUTION_FAILED", "LEASE_EXPIRED"] },
    "actor": {
      "type": "object", "additionalProperties": false,
      "required": ["kind", "id", "authenticated_workload"],
      "properties": {
        "kind": { "enum": ["human", "agent", "service", "system"] },
        "id": { "$ref": "common#/$defs/ActorSubjectId" },
        "authenticated_workload": { "type": ["string", "null"], "maxLength": 256 }
      }
    },
    "occurred_at": { "$ref": "common#/$defs/Timestamp" },
    "payload": {
      "type": "object", "additionalProperties": false,
      "properties": {
        "approval_id": { "oneOf": [{ "$ref": "common#/$defs/ApprovalId" }, { "type": "null" }] },
        "epoch_id": { "oneOf": [{ "$ref": "common#/$defs/EpochId" }, { "type": "null" }] },
        "vote_id": { "oneOf": [{ "$ref": "common#/$defs/VoteId" }, { "type": "null" }] },
        "approval_state": { "enum": ["PENDING", "PARTIALLY_APPROVED", "REVIEW_REQUIRED", "APPROVED", "REJECTED", "EXPIRED", "ESCALATED", "WITHDRAWN", "OVERRIDDEN", null] },
        "token_jti_hash": { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }], "description": "Hash of jti; raw bearer capability is never evidence payload." },
        "lease_id": { "oneOf": [{ "$ref": "common#/$defs/LeaseId" }, { "type": "null" }] },
        "result_hash": { "oneOf": [{ "$ref": "common#/$defs/Sha256Hex" }, { "type": "null" }] },
        "failure_code": { "type": ["string", "null"], "maxLength": 120 },
        "reason": { "type": ["string", "null"], "maxLength": 500 }
      }
    },
    "stream_id": { "$ref": "common#/$defs/AdrStreamId" },
    "sequence_number": { "type": "integer", "minimum": 0 },
    "prev_hash": { "$ref": "common#/$defs/Sha256Hex" },
    "record_hash": { "$ref": "common#/$defs/Sha256Hex" },
    "hash_alg": { "const": "SHA-256" },
    "canonicalization": { "const": "RFC8785" },
    "immutable_receipt_ref": { "type": ["string", "null"], "maxLength": 256,
      "description": "Receipt for publication into the immutable evidence corpus. Required before financial_write token redemption (I-25)." }
  }
}
```

---

## 3. API Contracts (OpenAPI 3.1 excerpt)

Conventions: bearer/mTLS auth on every route (ADR-001); `tenant_id` derived from the token, never from the body (INVARIANT I-3); errors use RFC 9457 problem+json; all mutating POSTs are idempotent on `request_id`/`Idempotency-Key`. If concurrent `/v1/authorize` writers race on the same `(tenant_id, request_id)`, the uniqueness loser re-reads and returns the committed decision when `context_hash` matches; an unreadable winner or a different context is 409, never `evidence_write_failed`. Execution capability routes additionally require the peer mTLS/SPIFFE identity to equal `authorized_executor`; ordinary tenant authentication is insufficient (I-23, V-17). v1 terminates mTLS in-process with mandatory client-certificate verification and derives workload identity only from exactly one SPIFFE URI SAN; headers, CN, and subject DN never establish identity.

### 3.1 Mandatory pre-evaluation enrichment

Before any policy is evaluated, `/v1/authorize` runs enrichment in this order. Every step **fails closed** — a miss is `422`, never a default:

1. **Token → tenancy.** `tenant_id`, agent identity, delegation claims come from the validated token (I-3). A body `tenant_id` that disagrees → `403`.
2. **Agent lookup.** Must exist in tenant and be `ACTIVE|MONITORED`, else `403 agent_not_active`.
3. **Tool lookup.** Must exist, must permit this agent, yields `risk_tier` floor, `binding_profile`, execution timings, and the allowlisted executor workloads. The server selects exactly one `authorized_executor`; the caller cannot supply it (V-21). Unknown tool, binding-profile version, or executor mapping → `422`.
4. **Resource enrichment.** `resource_owner` and `data_classification` are reconciled against the tool/resource registry (V-7). Caller may raise classification, never lower it. Unresolvable ownership → `422`, never a null in evidence.
5. **Binding check.** The server applies the hard 64 KiB/depth-16/256-key/finite-number budget to transient `tool.arguments`, validates every pointer under the declared profile, computes `parameters_hash` over the bound subset, and rejects a caller-sent mismatch. Unknown pointers follow `unknown_pointer_policy` (default reject → `400`). Raw arguments are excluded from persisted context/evidence and policy evaluation.
6. **Projection.** Any external data is already reduced to `mapped.fields` (§2.8). Raw envelopes are rejected at this endpoint.

Only after all six does evaluation begin — which is what makes rule 7 (input acceptance implies evidence representability) mechanically true rather than aspirational.

### 3.2 Tiered admission control

After identity and the authoritative risk source are resolved, but before evaluation or a protected
mutation runs, Mizan applies a per-process token bucket keyed by authenticated `tenant_id`, route
class (`authorize`, `approval`, `execution_token`) and risk tier. `/v1/authorize` uses the stored
tool risk floor; approval mutations and execution-token issuance use the originating ADR_Record's
immutable `risk.level`. Caller input never chooses the bucket.

`MIZAN_RATE_LIMITS_PER_MINUTE` gives the LOW, MEDIUM, HIGH and CRITICAL capacities in that order.
The default is `60,120,240,480`; values must be positive and strictly increasing so LOW exhausts
before MEDIUM and CRITICAL remains last to shed. Buckets refill continuously and start full. Every
route class has an independent bucket. Exhaustion returns 429 `rate_limit_exceeded` with the problem
type `https://mizan.ai/problems/rate_limit_exceeded`; it writes no decision, vote, approval
transition or capability. Limits and refusals are exported on the private metrics listener. Quotas
are per replica, not cluster-global; an N-replica deployment has N independently enforced shares.
An authorize retry that returns the already-recorded decision, and execution-token reissue that
returns the already-outstanding token, consume no new capacity because they do not repeat the
protected evaluation or minting work. Rate limiting does not weaken idempotency.

```yaml
openapi: 3.1.0
info: { title: Mizan Control Plane API, version: "1.1.0" }
x-sla:
  authorize_p95_ms: 50        # cached/simple decisions (PRD §47, §62)
  authorize_complex_p95_ms: 150
  registry_read_p95_ms: 100
  registry_write_p95_ms: 250
  availability: "99.9%"
  throughput_target: "500-1000 decisions/sec per cluster"

paths:

  /auth/login:
    get: { summary: "Begin customer-IdP OIDC Authorization Code + PKCE login; state and nonce are one-use", responses: { "303": {description: Redirect to the configured customer IdP} } }
  /auth/callback:
    get: { summary: "Validate state, nonce, issuer, audience, signature, MFA and group mapping; issue an opaque server-side workforce session", responses: { "303": {description: Local return redirect with Secure HttpOnly session cookie}, "401": {description: OIDC exchange or token validation failed}, "403": {description: Principal, group, MFA or control-domain mapping refused} } }
  /auth/session:
    get: { summary: "Return the current tenant-scoped workforce session without exposing IdP tokens", responses: { "200": {description: Session identity, roles/domains, strength, step-up and expiry}, "401": {description: Missing, expired, invalid or revoked session} } }
  /auth/step-up:
    get: { summary: "Begin a fresh prompt=login OIDC authentication for a HIGH/CRITICAL vote", responses: { "303": {description: Redirect to IdP with configured MFA/hardware ACR values} } }
  /auth/logout:
    post: { summary: "Revoke the current workforce session and clear its cookie", responses: { "204": {description: Logged out} } }
  /auth/sessions/{session_id}/revoke:
    post: { summary: "Revoke a tenant-scoped workforce session; requires the mapped session.admin role", responses: { "204": {description: Revoked}, "403": {description: session.admin role absent}, "404": {description: Session absent in tenant} } }

  /v1/authorize:
    post:
      summary: Evaluate a proposed agent action (the heartbeat API, PRD §86)
      x-sla-p95-ms: 50
      requestBody:
        required: true
        content: { application/json: { schema: { $ref: "https://mizan.ai/schemas/evaluation_context/1.2.json" } } }
      responses:
        "200":
          description: Decision rendered (including DENY — a deny is a successful evaluation)
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                required: [decision_id, decision, risk, policies, reasons, degraded]
                properties:
                  decision_id: { type: string }
                  decision:    { enum: [ALLOW, DENY, REQUIRE_APPROVAL, CONSTRAIN, REDACT, ESCALATE] }
                  risk:        { type: object, properties: { level: { enum: [LOW, MEDIUM, HIGH, CRITICAL] },
                                                             floor_source: { enum: [risk_engine, tool_registry_floor, degraded_floor] } } }
                  policies:    { type: array, items: { type: object, properties: { policy_id: {type: string}, version: {type: integer}, content_hash: {type: string} } } }
                  reasons:     { type: array, items: { type: string } }
                  constraints: { type: [object, "null"] }
                  degraded:    { type: object, properties: { is_degraded: {type: boolean}, reason: {type: string}, grant_ref: {type: [string, "null"]} } }
                  approval:    { type: [object, "null"],
                                 properties: { approval_id: {type: string}, state: {type: string},
                                               current_epoch_id: {type: string}, epoch_number: {type: integer},
                                               quorum: {type: integer}, expires_at: {type: string} } }
                  execution_token: { type: [string, "null"],
                    description: "Present only on ALLOW/CONSTRAIN/REDACT. Single-use; claims per §2.10; TTL from tool/policy token_ttl_seconds (default 300s) and governs time-to-START only." }
        "400": { description: "Malformed EvaluationContext, or an argument pointer unclassified by the binding profile" }
        "401": { description: Agent identity not authenticated }
        "403": { description: "Agent not ACTIVE/suspended/outside tenant, or body tenant_id disagrees with token" }
        "409": { description: Idempotency conflict (same request_id, different context_hash) }
        "422": { description: "Enrichment failure: unknown agent/tool/policy/binding-profile reference, or unresolvable resource ownership/classification (§3.1)" }
        "429": { description: "Tenant/risk/route bucket exhausted; problem type is https://mizan.ai/problems/rate_limit_exceeded" }
        "503": { description: "FAIL-CLOSED. Engine degraded; HIGH/CRITICAL paths must treat as DENY (ADR-003)" }

  /v1/agents:
    post: { summary: Register agent, x-sla-p95-ms: 250,
            responses: { "201": {description: Created}, "409": {description: agent_id exists} } }
    get:  { summary: List agents (tenant-scoped), x-sla-p95-ms: 100, responses: { "200": {description: OK} } }
  /v1/agents/{agent_id}:
    get:   { summary: Fetch agent, responses: { "200": {description: OK}, "404": {description: Not found in tenant} } }
    patch: { summary: "Lifecycle/config change (dual-control when the stored OR the submitted document is a production HIGH/CRITICAL agent — see V-22)",
             responses: { "200": {description: OK}, "403": {description: Missing second approver}, "422": {description: "Delegation parent has not authorized this edge"} } }

  /v1/tools:
    post: { summary: "Register tool (§2.6: schema, owner, risk_tier, data_classification, permitted_agents, binding_profile, execution timings). Registry writes require a human operator with MFA or hardware authentication, and four eyes for a production HIGH/CRITICAL object (V-22).",
            responses: { "201": {description: Created}, "400": {description: "binding_profile bound_pointers empty or overlapping volatile_pointers"}, "403": {description: "registry_write_auth_insufficient or registry_dual_control_required"} } }
  /v1/tools/{tool_id}:
    get: { summary: Fetch tool, responses: { "200": {description: OK}, "404": {description: Not found} } }
  /v1/tools/{tool_id}/binding-profile:
    post: { summary: "Publish a new binding-profile version (immutable; never edited in place — old tokens reference old versions)",
            responses: { "201": {description: Created}, "409": {description: Version exists} } }

  /v1/policies:
    post: { summary: Create policy (status=DRAFT), responses: { "201": {description: Created} } }
  /v1/policies/{policy_id}:
    get: { summary: Fetch policy (any stored version via ?version=), responses: { "200": {description: OK} } }
  /v1/policies/{policy_id}/simulate:
    post:
      summary: Dry-run a policy against a sample EvaluationContext (PRD §90). Never emits events or ADR_Records.
      x-sla-p95-ms: 100
      responses: { "200": { description: "Simulated decision + matched-condition explanation" } }
  /v1/policies/{policy_id}/transition:
    post: { summary: "Lifecycle transition per §5.4 (approver ≠ author enforced here)",
            responses: { "200": {description: OK}, "409": {description: Illegal transition} } }

  /v1/approvals:
    get: { summary: "Approver queue: approvals awaiting a decision, tenant-scoped, newest first (filters: state; cursor pagination). Each item carries the current epoch's kind, quorum, votes cast, eligible roles and expiry.",
           x-sla-p95-ms: 200, responses: { "200": {description: OK} } }
  /v1/approvals/{approval_id}:
    get: { summary: "Approval status: state, current epoch, per-epoch votes and eligibility snapshot hash",
           responses: { "200": {description: OK} } }
  /v1/approvals/{approval_id}/votes:
    post:
      summary: Cast one approver vote into the CURRENT epoch (drives §5.2 state machine)
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [vote, epoch_number]
              properties:
                vote:          { enum: [APPROVE, REJECT, ABSTAIN] }
                epoch_number:  { type: integer, minimum: 1,
                                 description: "The epoch the voter believes is current. Mismatch → 409 with the current epoch in the problem body. Prevents a vote racing an escalation from landing in the wrong authority set." }
                role_claim:    { type: [string, "null"],
                                 description: "Optional: which eligible role the voter votes under. Validated against the epoch eligibility snapshot; the RECORDED role and control_domain come from the snapshot, not from this field." }
                justification: { type: [string, "null"], maxLength: 2000, description: "Required in override epochs (V-5)" }
                comment:       { type: [string, "null"], maxLength: 2000 }
      responses:
        "200": { description: "Vote recorded; response carries new ApprovalState and epoch tallies" }
        "403": { description: "Self-approval, not in eligibility snapshot, insufficient auth_strength, duplicate vote, or non-human identity" }
        "409": { description: "Stale epoch_number (escalation/override raced this vote), or approval already terminal" }
        "429": { description: "Tenant/risk/approval bucket exhausted; no vote recorded" }
  /v1/approvals/{approval_id}/escalate:
    post: { summary: "Close the current epoch and open an escalation epoch atomically (§5.2). Idempotent per epoch_number.",
            responses: { "200": {description: OK}, "409": {description: "Epoch already closed, or max_epochs reached"}, "429": {description: "Rate limited; no epoch transition"} } }
  /v1/approvals/{approval_id}/override:
    post: { summary: "Break-glass: open an override epoch. Requires Policy.approval_requirements.override, fresh quorum, justification; emits high-severity events. Never unilateral unless the tenant explicitly configured quorum=1.",
            responses: { "200": {description: Override epoch opened}, "403": {description: "No override configured for this policy, or caller not in eligible_roles"}, "429": {description: "Rate limited; no override epoch"} } }
  /v1/approvals/{approval_id}/withdraw:
    post: { summary: Requester withdraws pending request, responses: { "200": {description: OK}, "429": {description: "Rate limited; request remains pending"} } }

  /v1/actions/{decision_id}/execute:
    post:
      summary: "Redeem execution_token ATOMICALLY for an ExecutionLease (§2.11). Token TTL governs time-to-start; lease governs duration. Peer SPIFFE identity must match authorized_executor; financial_write additionally requires an immutable evidence receipt (I-23, I-25)."
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [execution_token, arguments]
              properties:
                execution_token: { type: string }
                arguments: { type: object, maxProperties: 256, description: "Same bounded transient arguments presented for authorization; server recomputes the binding hash using the pinned profile." }
                idempotency_key: { type: [string, "null"], maxLength: 128 }
      responses:
        "200": { description: "Lease granted (or the SAME lease returned for a repeated idempotency_key — retry, not re-authorization)" }
        "403": { description: "Token invalid, expired, already redeemed, issuer/audience/executor mismatch, binding-profile mismatch, missing required immutable receipt, or context_hash drift since approval (I-9, I-23, I-25)" }
  /v1/actions/{decision_id}/lease/{lease_id}/heartbeat:
    post: { summary: "Extend a running execution lease (bounded by max_extensions). Caller workload identity MUST equal lease.authorized_executor.",
            responses: { "200": {description: Extended}, "403": {description: "Authenticated workload is not the lease executor"}, "409": {description: "Lease expired or extension budget exhausted"} } }
  /v1/actions/{decision_id}/lease/{lease_id}/complete:
    post: { summary: "Record execution outcome; appends an immutable DecisionEvent (§2.12). Caller workload identity MUST equal lease.authorized_executor.",
            responses: { "200": {description: Recorded}, "403": {description: "Authenticated workload is not the lease executor"}, "409": {description: Lease not active} } }

  /v1/decisions/{decision_id}:
    get: { summary: Fetch immutable ADR_Record + ordered DecisionEvents, responses: { "200": {description: OK} } }
  /v1/decisions/{decision_id}/context:
    get:
      summary: "Fetch the immutable normalized policy context and its recorded context_hash for replay. Raw tool arguments are never returned."
      responses:
        "200":
          description: Stored context
          content:
            application/json:
              schema: { $ref: "https://mizan.ai/schemas/context_response/1.0.json" }
        "404": { description: Decision context not found in the authenticated tenant }
  /v1/decisions/{decision_id}/execution-token:
    post:
      summary: "Issue the ExecutionToken (§2.10) a decision earned. Permitted after ALLOW, or after the decision's approval reaches APPROVED/OVERRIDDEN. Only the agent principal named by the ADR_Record may ask (V-23). At most one unconsumed, unexpired token exists per decision: a repeat request returns the outstanding one rather than granting a second capability. `authorized_executor` is chosen from the tool version's registered set (V-21); a caller may name one of them and never propose a new one."
      requestBody:
        content:
          application/json:
            schema: { type: object, additionalProperties: false,
                      properties: { executor_spiffe_id: { oneOf: [ { $ref: "common#/$defs/SpiffeId" }, { type: "null" } ] } } }
      responses: { "200": {description: "Issued or reissued; body carries execution_token, expires_at, reused"},
                   "403": {description: "approval_incomplete, decision_not_executable, execution_token_requester_mismatch, or executor_not_authorized"},
                   "404": {description: Decision not found in tenant},
                   "429": {description: "Tenant/risk/execution-token bucket exhausted; no capability minted"},
                   "422": {description: "Tool has several registered executors and none was named"} }
  /v1/decisions:
    get: { summary: "Search ADRs (filters: agent, tool, decision, risk, principal, customer, time range; cursor pagination)",
           x-sla-p95-ms: 500, responses: { "200": {description: OK} } }

  /v1/audit:
    get: { summary: Search audit trail (tenant-scoped, cursor pagination), responses: { "200": {description: OK} } }
  /v1/audit/verify:
    post:
      summary: "Verify hash-chain integrity for a stream range; returns first broken link if any (ADR-004). Uses checkpoints so verification is O(range), not O(history)."
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [stream_id]
              properties:
                stream_id: { type: string }
                from_sequence: { type: [integer, "null"] }
                to_sequence:   { type: [integer, "null"] }
                verify_anchors: { type: boolean, default: true }
      responses:
        "200": { description: "Chain intact; response lists checkpoints covered and anchor signatures verified" }
        "409": { description: "Tamper evidence found (first broken link + expected/actual hashes)" }
  /v1/audit/anchors:
    get: { summary: "List signed checkpoints/anchors for a stream (compliance evidence export)", responses: { "200": {description: OK} } }
  /v1/audit/keys:
    get:
      summary: "Publish additive verification key history for evidence, execution, and degraded-grant signatures"
      responses:
        "200": { description: "Keyset items include key_id, role, algorithm, public_key, not_before, not_after, and revoked_at" }

  /v1/risk/evaluate:
    post: { summary: Standalone risk scoring for a context (used by authorize internally; exposed for tooling),
            x-sla-p95-ms: 30, responses: { "200": {description: OK} } }
```

---

## 4. Event Taxonomy

All events: CloudEvents 1.0 envelope, `source = /mizan/{tenant_id}/{component}`, `subject` = primary object id, payload validated against §2 schemas. **Events are published through the transactional outbox only** (ADR-004 Amendment A) — no component writes to Postgres and Kafka independently. Kafka is delivery infrastructure, not the evidence corpus.

| Event type | Emitted when | Payload core | Consumers |
|---|---|---|---|
| `mizan.agent.registered` | Agent created | Agent | audit, dashboard |
| `mizan.agent.lifecycle_changed` | Any §5.3 transition | agent_id, from, to, actor | audit, SIEM |
| `mizan.agent.suspended` | SUSPENDED entered (manual or automated) | agent_id, reason | SIEM, alerting |
| `mizan.tool.registered` | Tool created | Tool | audit |
| `mizan.tool.binding_profile_published` | New binding-profile version | tool_id, profile_id, version | audit, SDK cache |
| `mizan.policy.created` / `.transitioned` | Policy lifecycle §5.4 | policy_id, version, from, to, actor, approver | audit, cache invalidation |
| `mizan.authorization.requested` | /v1/authorize received | EvaluationContext (redacted) | observability |
| `mizan.authorization.allowed` | decision ∈ {ALLOW, CONSTRAIN, REDACT} | ADR_Record ref | audit, dashboard |
| `mizan.authorization.denied` | decision = DENY | ADR_Record ref, reasons | SIEM, dashboard |
| `mizan.authorization.approval_required` | decision = REQUIRE_APPROVAL | ADR ref, approval_id, epoch, quorum | workflow/approval providers |
| `mizan.authorization.failed_closed` | 503 fail-closed path taken | context_hash, component | SIEM, paging |
| `mizan.authorization.degraded_allow` | LOW-risk degraded grant exercised | decision_id, grant_ref, component | SIEM, compliance |
| `mizan.approval.requested` | Approval + initial epoch created | approval_id, epoch, roles, quorum, expires_at | approval providers (UI, ServiceNow, Slack…) |
| `mizan.approval.vote_cast` | Each individual vote | approval_id, epoch, approver, control_domain, vote | audit |
| `mizan.approval.partially_approved` | Vote recorded, quorum not yet met | approval_id, epoch, votes/quorum | dashboard |
| `mizan.approval.epoch_opened` | Escalation/override/review epoch opened | approval_id, epoch_number, kind, pool_mode, carry_forward | workflow, audit |
| `mizan.approval.epoch_closed` | Previous epoch superseded/terminal | approval_id, epoch_number, outcome | audit |
| `mizan.approval.approved` | Quorum met | approval_id, decision_id, deciding_epoch | executor, agent resume |
| `mizan.approval.rejected` | Rejection threshold met per `rejection_mode` | approval_id, epoch, rejectors | agent resume (deny path) |
| `mizan.approval.review_required` | First REJECT under `review_required` mode | approval_id, epoch, reviewer_pool | workflow |
| `mizan.approval.overridden` | Override epoch met quorum | approval_id, overriders, justification | SIEM (high severity), compliance, tenant admin |
| `mizan.approval.expired` | Epoch TTL elapsed with no further epoch | approval_id | audit, requester notify |
| `mizan.approval.escalated` | Escalation triggered | approval_id, escalation_role, epoch | workflow |
| `mizan.execution.leased` | Token redeemed → lease created | decision_id, lease_id, expires_at | observability |
| `mizan.execution.lease_expired` | Lease lapsed without completion | decision_id, lease_id | SIEM, dashboard |
| `mizan.tool.executed` | Execution outcome recorded | decision_id, lease_id, status, result_hash | audit, behavioral baseline |
| `mizan.integration.schema_drift` | External payload carried unmapped fields | provider, projection_id, dropped_fields | integration ops |
| `mizan.security.prompt_injection` | Detector hit (Phase 1) | agent_id, trace_id, severity | SIEM |
| `mizan.security.data_exposure` | DLP/PII hit | agent_id, classification, disposition | SIEM |
| `mizan.security.redaction_failed` | DLP scan failed or manifest incomplete | audit ref, dlp.status | SIEM (write is rejected — I-19) |
| `mizan.security.anomaly` | Behavioral deviation (Phase 1) | agent_id, baseline_ref, observed | SIEM |
| `mizan.audit.anchor_written` | Signed checkpoint published to WORM | stream_id, sequence range, head_hash, anchor_ref | compliance evidence |

---

## 5. State Machines

### 5.1 Authorization request lifecycle

```text
RECEIVED ──enrich (§3.1, fail-closed)──► EVALUATING ──┬─► ALLOW ──────────► token issued ─► (execution SM §5.5)
                              │                        ├─► CONSTRAIN/REDACT/ESCALATE ─► DENY evidence + 501 NOT_IMPLEMENTED
                              │                        ├─► DENY ────────────► terminal (ADR written)
                              │                        ├─► REQUIRE_APPROVAL ─► (approval SM §5.2)
                              │                        └─► ESCALATE ────────► routed to security review, no token
                              ├─(enrichment miss)──► 422 (no decision, no ADR — nothing was evaluated)
                              └─(engine unavailable)─► FAIL_CLOSED (503; DENY-equivalent for MEDIUM+,
                                                       degraded-allow only for LOW under a valid grant — ADR-003)
```

Every state that renders a **decision** writes exactly one ADR_Record before the HTTP response is sent (INVARIANT I-1). A `422` enrichment miss is not a decision: nothing evaluated, nothing to record beyond an audit entry.

**No matching ACTIVE policy is always `DENY`.** It is not tenant-configurable. The ADR_Record uses `decision_basis=default_deny` with `policies=[]`, so the safest path remains schema-valid and auditable (V-15). Risk or policy-engine failure produces a `DENY`, `decision_basis=system_fail_closed`, `policies=[]` record before returning HTTP 403 `authorization_failed_closed`; a degraded grant uses `degraded_grant`. If that fail-closed evidence write also fails, Mizan returns 503 `fail_closed_evidence_write_failed`, increments the dedicated `system_fail_closed_evidence_write_failed` counter, and emits a critical alert because no truthful record can exist.

### 5.2 REQUIRE_APPROVAL state machine (multi-party banking workflows)

Configured by `Policy.approval_requirements`. **Authority lives in epochs** (§2.7): an epoch fixes quorum, eligibility snapshot, rejection mode, and deadline. Votes bind to an epoch; escalation and override close one epoch and open the next atomically.

```text
                      REQUIRE_APPROVAL
                             │ create approval + EPOCH 1 (kind=initial, quorum=M, TTL, eligibility snapshot)
                             ▼
                        ┌─────────┐  requester cancels   ┌───────────┐
        ┌──────────────►│ PENDING ├─────────────────────►│ WITHDRAWN │ (terminal)
        │               └────┬────┘                      └───────────┘
        │   APPROVE (count   │
        │   < quorum)        │            REJECT ─── rejection_mode ───┐
        │                    ▼                                          │
        │        ┌─────────────────────┐                    veto │ rejection_quorum │ review_required
        │        │ PARTIALLY_APPROVED  │                          ▼           ▼            ▼
        │        └──────┬──────────────┘                    ┌──────────┐ ┌──────────┐ ┌──────────────────┐
        │               │ APPROVE → count == quorum         │ REJECTED │ │ count<K: │ │ REVIEW_REQUIRED  │
        │               │ (distinct identities; distinct    │(terminal)│ │  stay    │ │ → review epoch   │
        │               │  control domains if dual control) └──────────┘ │  pending │ └──────────────────┘
        │               ▼                                                 └──────────┘
        │        ┌──────────┐  context_hash re-check OK   ┌──────────┐
        │        │ APPROVED ├────────────────────────────►│  LEASED  │─► EXECUTING ─► EXECUTED
        │        └────┬─────┘   (token redeemed §5.5)     └──────────┘   (append DecisionEvent)
        │             │ context drift detected
        │             └────────► back to /v1/authorize (fresh evaluation, new ADR)
        │
        │  at trigger_fraction × TTL, escalation configured      TTL elapsed, no further epoch
        │        │                                                       │
        │        ▼  ATOMIC: close epoch N (CLOSED_SUPERSEDED)            ▼
        │  ┌───────────┐   open epoch N+1 (kind=escalation,        ┌─────────┐
        └──┤ ESCALATED ├── pool_mode, carry_forward, reset_expiry) │ EXPIRED │ (terminal, fail-closed)
           └───────────┘   → back to PENDING in epoch N+1          └─────────┘

  Break-glass: /override → ATOMIC close current epoch, open epoch (kind=override, fresh quorum,
  justification required, no carried votes) → quorum met ⇒ OVERRIDDEN (terminal-allow, high-severity events).
```

**Epoch transition semantics (the v1.0 ambiguity, now closed):**

| Question | v1.3 answer |
|---|---|
| Does escalation replace or augment the approver pool? | `escalation.pool_mode` — explicit, no runtime default (V-3). |
| Do earlier APPROVE votes still count? | Only if `carry_forward_votes = true`, and only while the voter is still in the **new** epoch's eligibility snapshot. Carried votes keep their original `epoch_id` in evidence. |
| May original approvers still vote? | Only if `pool_mode = augment` and they appear in the new snapshot. |
| Does the TTL restart? | `escalation.reset_expiry` — explicit. |
| What happens to a vote racing the escalation? | The vote cites `epoch_number`; the escalation closes epoch N in the same transaction that opens N+1. A vote citing N after that commits gets `409` with the current epoch — it is never silently re-homed into N+1. |
| Which role counts when an approver holds several? | The epoch's eligibility snapshot assigns exactly one `control_domain` per member. The recorded role comes from the snapshot, never from client-supplied text. |
| Where does control-domain authority come from? | A reviewed, versioned Mizan tenant role-registry mapping populated from IdP data. The epoch pins `authority_mapping_version`; live IdP claims never redefine an open epoch. |

**Guards (all enforced server-side, all violations → 403 + audit event):**

| # | Guard |
|---|---|
| G1 | No self-approval: `approver_id ≠ ADR.principal.id`, and `approver_id` is not the accountable owner of any agent in the delegation chain. |
| G2 | Approver must be a human identity with `auth_strength ∈ {mfa, hardware}`; agents and service identities can never vote. |
| G3 | One vote per `approver_id` per **epoch**; votes are immutable. (An identity holding two roles still votes once.) |
| G4 | The approver must appear in the epoch's immutable eligibility snapshot. If `distinct_roles_required`, counted APPROVEs must come from distinct **control domains** — independently administered authority groups, not merely distinct role labels (PRD §28 "MULTI-APPROVAL", ADR-007). |
| G5 | Rejection is governed by `rejection_mode`: `veto` (any REJECT terminal — the correct default for sanctions/fraud controls), `rejection_quorum` (terminal at K REJECTs), or `review_required` (first REJECT opens a review epoch under an independently controlled pool). Quorum never overrides a completed rejection. |
| G6 | APPROVED does not execute directly: execution requires atomic redemption of the single-use `execution_token`, re-validation of `context_hash`, matching `binding_profile` version, and the agent still being ACTIVE. |
| G7 | Terminal states (APPROVED-and-executed, REJECTED, EXPIRED, WITHDRAWN, OVERRIDDEN) are immutable; late votes get 409. Closed epochs accept no votes. |
| G8 | Every transition appends to the ADR amendment log and enqueues the matching `mizan.approval.*` event **in the same transaction** (outbox pattern — never a dual write). |
| G9 | Override requires `approval_requirements.override` to be configured, a fresh quorum in an override epoch, a non-empty justification per voter, and high-severity notification. A silent unilateral override is impossible by construction. |

### 5.3 Agent lifecycle (PRD §48)

```text
PROPOSED → ASSESSED → DESIGNED → SECURITY_REVIEW → APPROVED → REGISTERED → ACTIVE ⇄ MONITORED
ACTIVE|MONITORED → SUSPENDED → REVIEWED → { ACTIVE (reinstated) | RETIRED }
Any state → RETIRED (with dual-control for production HIGH/CRITICAL agents)
```
Only `ACTIVE`/`MONITORED` agents can receive ALLOW; `SUSPENDED`+ always evaluates to DENY with reason `agent_not_active`.

### 5.4 Policy lifecycle (PRD §91)

```text
DRAFT → TESTED → APPROVED → ACTIVE → SUPERSEDED → RETIRED
```
Guards: `TESTED` requires ≥1 recorded simulation run; `APPROVED` requires non-null `approver ≠ author` (schema-enforced, §2.2 `allOf`); activating version N sets version N-1 to `SUPERSEDED` atomically; only `ACTIVE` policies participate in evaluation, but all versions remain queryable forever (audit reconstruction: "which policy version allowed this on March 12").

### 5.5 Execution lifecycle (token → lease)

```text
token issued ──redeem (atomic CAS on jti)──► LEASED ──start──► EXECUTING ──┬─► EXECUTED (amend ADR, result_hash)
      │                                        │                            └─► FAILED   (amend ADR)
      │                                        └──no heartbeat within lease_ttl──► LEASE_EXPIRED
      └──not redeemed within token_ttl──► token expires (no execution; agent must re-authorize)

retry of the SAME execution = same idempotency_key against the SAME lease (not a new authorization)
```

`token_ttl_seconds` bounds **time-to-start**; `lease_ttl_seconds` + heartbeats bound **duration**. A 40-minute KYC extraction therefore needs a 300 s token and a heartbeated lease — not a 40-minute token (ADR-008).

---

## 6. Invariants (the test-generation contract)

Reasoning/test agents fuzz against these. Each maps to at least one property-based or integration test.

| ID | Invariant |
|---|---|
| I-1 | No tool execution without a prior ADR_Record whose decision permits it. (No ADR → no action.) |
| I-2 | For every stream, hash chains are contiguous: `record[n].prev_hash == record[n-1].record_hash` and `sequence_number` has no gaps. |
| I-3 | No API response ever contains an object whose `tenant_id` differs from the caller's token tenant. Tenant comes from the token, never the payload. |
| I-4 | `len(delegation_chain) ≤ max_delegation_depth + 1`, chain is non-empty, and every adjacent pair is an explicitly allowed delegation edge. |
| I-5 | A child agent's effective permission set ⊆ (its own registered tools ∩ tools delegable by its parent). Inheritance is never additive. |
| I-6 | An approval reaches APPROVED only with ≥ quorum distinct APPROVE votes satisfying G1–G4 within a single deciding epoch (plus validly carried votes); rejection resolves per `rejection_mode`. |
| I-7 | If the policy engine, policy cache, or risk engine is unreachable, MEDIUM+ contexts always resolve to DENY/503 (fail-closed); degraded-allow is possible only for LOW risk under a valid grant (ADR-003). |
| I-8 | Every policy cited by an ADR_Record was ACTIVE at evaluation time and is pinned as `(policy_id, version, content_hash)`. A `default_deny` or `system_fail_closed` record cites zero policies and pins the evaluator/configuration version through its evidence metadata (V-15). |
| I-9 | A deferred (approved) execution runs only if the current `context_hash` equals the hash captured at decision time; drift forces re-evaluation. |
| I-10 | `execution_token` is single-use (atomic CAS on `jti`), TTL-bound by tool/policy config, and bound to `(tenant_id, agent_id, principal_id, delegation_chain_hash, authorized_executor, decision_id, tool_id, binding_profile, parameters_hash, context_hash[, approval_epoch_id])`. Replay → 403 + `mizan.security.*` event. |
| I-11 | ADR_Records and AuditTrail entries are append-only: no UPDATE/DELETE grants exist for runtime roles, and every production anchor is externally timestamped by at least one RFC 3161 authority and verified offline against an operator-supplied trust root. Final tokens are append-only `anchor_attestations` sidecars; they never rewrite the signed anchor. Assurance is derived per anchor and the stream takes the weakest result. Development anchors are explicitly `unattested` and never satisfy or claim this production invariant. Offline verification of the timestamp holds for the lifetime of the authority's signing certificate and no longer: the attestation declares that date, reaching it is the distinct `EXPIRED` verdict rather than a failure, and the chain, receipts and anchor signatures still verify past it (`docs/spec/EVIDENCE-BUNDLE-FORMAT.md` sections 4 and 5). |
| I-12 | The stored audit `payload` is post-redaction and `stored_payload_hash` commits to exactly what is stored; the pre-redaction commitment is **keyed** (HMAC), never a bare hash, so low-entropy PII is not recoverable by dictionary attack. |
| I-13 | **Representability:** every request that passes `EvaluationContext` validation plus §3.1 enrichment yields a schema-valid `ADR_Record`. No decision is renderable that cannot be recorded. Property test: generate valid contexts, assert ADR construction never fails. |
| I-14 | Every issued token carries a complete, non-null binding tuple; `parameters_hash` is computed only over `bound_pointers` of the cited profile version, so a retry that changes only `volatile_pointers` still redeems, and a change to any bound pointer never does. |
| I-15 | Votes bind to exactly one epoch. A vote citing a non-current `epoch_number` is rejected `409`. Quorum is evaluated within one epoch, counting only carried votes whose voter is in that epoch's eligibility snapshot. |
| I-16 | No ID field accepts a value carrying another type's prefix (`pol_…` in a `tool_id` field is a validation error, not a lookup miss), and storage rejects it again as a typed foreign key on `(tenant_id, id)`. |
| I-17 | Foreign payload data never reaches policy evaluation except as `mapped.fields` produced by an allowlisted, versioned projection; the raw envelope is never a condition input, and an adapter failure surfaces as a controlled tool error, never a service fault. |
| I-18 | No stored audit `payload` contains a field classified `pii` or `secret`; such fields exist only as manifest commitments or, under legal hold, as an encrypted `evidence_ref`. |
| I-19 | Every audit record whose payload could carry classified data carries a complete redaction attestation (policy id/version/hash, redactor build, DLP status). Missing or `scan_failed` attestation rejects the write and emits `mizan.security.redaction_failed` — fail-closed, not best-effort. |
| I-20 | Sequence numbers are allocated inside the committing transaction against the chain-head row; an aborted or rolled-back write consumes no sequence number, so I-2 gaps mean tampering rather than a rollback artefact. |
| I-21 | `fail_open_allowed` is honoured only when the evaluated risk floor is LOW **and** a cryptographically verified, unexpired, unrevoked `DegradedModeGrant` from the tenant issuer trust registry covers the failed component. Default is false on every policy, including imports. |
| I-22 | An override reaches OVERRIDDEN only via an override epoch with fresh quorum, per-voter justification, and emitted high-severity notification; no code path allows a silent or vote-free override. |
| I-23 | Token redemption, lease heartbeat, and completion require the authenticated mTLS/SPIFFE workload to equal the server-selected, tool-registry-authorized `authorized_executor` in the capability and lease; a capability issued to one agent/workload is unusable by another, even within the same tenant. |
| I-24 | The original ADR_Record is never cloned or updated to represent later state. Every approval/capability/lease/execution transition appends exactly one schema-valid DecisionEvent with dense per-decision ordering. |
| I-25 | A `financial_write` capability cannot be redeemed until its authorization/approval evidence has an immutable object-store publication receipt. LOW/MEDIUM non-financial actions may use the bounded asynchronous publication window configured in §8. |
| I-26 | A degraded ALLOW is executable only after its record is synchronously fsynced to an encrypted, capacity-bounded local WAL and a signed local receipt is returned. WAL full, fsync failure, missing key, or replay-deadline breach fails closed. |

---

## 7. SLA & Capacity Targets (engineering targets, not contractual — PRD §47, §62)

| Surface | Target |
|---|---|
| `POST /v1/authorize` (cached/simple) | **p95 < 50 ms** (includes §3.1 enrichment and RLS planner overhead) |
| `POST /v1/authorize` (complex, multi-policy + risk) | p95 < 150 ms |
| `POST /v1/risk/evaluate` | p95 < 30 ms |
| Registry reads / writes | p95 < 100 ms / < 250 ms |
| Decision search | p95 < 500 ms |
| Throughput | 500–1000 decisions/sec per cluster, horizontally scalable (chain sequencer sharded per stream — ADR-004) |
| Availability | 99.9% (enterprise tier 99.99%) |
| Decision → outbox drain → Kafka lag | < 2 s p95 |
| Approval vote → agent-resume signal | < 5 s p95 |
| `POST /v1/audit/verify` (100k-record range, checkpointed) | < 10 s; full-history replay is never on the interactive path |
| Token redemption (atomic CAS) | p95 < 20 ms |

---

## 8. Configuration Registry

Every behaviour that varies is named here (rule 9). "Scope" says who may set it; **tenant-overridable settings can never weaken a security default** — a tenant may make things stricter, and only the listed keys may be relaxed at all, under HUMAN-lane sign-off.

| Key | Default | Scope | Notes |
|---|---|---|---|
| `MIZAN_DATABASE_URL` | *(required)* | deployment | Runtime-role DSN. The application connects as `mizan_app`, never `mizan_owner`; RLS depends on it. |
| `MIZAN_JWT_ISSUER` | *(required)* | deployment | Exact accepted `iss` for identity tokens. |
| `MIZAN_JWT_AUDIENCE` | `mizan-control-plane` | deployment | Exact accepted `aud` for identity tokens. |
| `MIZAN_IDENTITY_JWKS` | *(required)* | deployment | Local public-only JWKS for identity-token verification. Every key requires a unique non-empty `kid`, explicit `use: sig`, and `alg` in `RS256`/`ES256`/`EdDSA`; symmetric and private keys are refused at startup. Rotation is old-only → old+new → new-only after at least `MIZAN_IDENTITY_TOKEN_MAX_TTL_SECONDS`; the token header selects only a configured `kid` and never a URL or trust root. |
| `MIZAN_IDENTITY_TOKEN_MAX_TTL_SECONDS` | `3600` | deployment | Maximum accepted `exp - iat` for an identity token. `exp` in the future is not a bounded lifetime, and there is no revocation path for identity tokens, so a token's lifetime is the whole of its blast radius. Refused as 401 `identity_token_ttl_excessive`. |
| `MIZAN_WORKFORCE_OIDC_AUTHORIZATION_ENDPOINT` | *(required in production)* | deployment | Customer IdP authorization endpoint. Production requires HTTPS; callers never select identity metadata. |
| `MIZAN_WORKFORCE_OIDC_TOKEN_ENDPOINT` | *(required in production)* | deployment | Customer IdP code-exchange endpoint. Production requires HTTPS and a bounded exchange. |
| `MIZAN_WORKFORCE_OIDC_CLIENT_ID` | *(required in production)* | deployment | Exact OIDC ID-token audience for the operator console. |
| `MIZAN_WORKFORCE_OIDC_CLIENT_SECRET` / `MIZAN_WORKFORCE_OIDC_CLIENT_SECRET_FILE` | *(required by the production API workload)* | deployment | Confidential-client credential. Prefer the file form; an unreadable file is refused and never falls back silently. It is not supplied to evidence background workers, which expose no workforce routes. |
| `MIZAN_WORKFORCE_OIDC_REDIRECT_URI` | *(required in production)* | deployment | Exact local callback URI registered at the IdP; HTTPS is mandatory in production. |
| `MIZAN_WORKFORCE_TENANT_ID` | *(required in production)* | deployment | Tenant served by this customer-IdP configuration. It selects an RLS scope but conveys no authority without the opaque session secret. |
| `MIZAN_WORKFORCE_GROUP_CLAIM` | `groups` | deployment | ID-token claim containing customer group strings. Non-array claims are refused. |
| `MIZAN_WORKFORCE_ROLE_MAPPING` | *(required in production)* | deployment | JSON object mapping each accepted customer group to non-empty `roles` and one `control_domain`. Ambiguous role/domain mappings fail closed; approval epoch snapshots remain authoritative. |
| `MIZAN_WORKFORCE_SESSION_TTL_SECONDS` | `900` | deployment | Opaque server-side workforce-session lifetime, bounded to 60–3600 seconds. The browser receives only a Secure HttpOnly SameSite=Lax cookie. |
| `MIZAN_WORKFORCE_STEP_UP_MAX_AGE_SECONDS` | `120` | deployment | Maximum age of the fresh IdP authentication immediately before a HIGH/CRITICAL vote; bounded to 30 seconds through the session TTL. |
| `MIZAN_WORKFORCE_STEP_UP_ACR_VALUES` | `urn:mizan:hardware,urn:mizan:mfa` | deployment | Ordered IdP ACR values requested with `prompt=login,max_age=0`; the callback must return one of them for step-up to succeed. |
| `MIZAN_MAX_REQUEST_BODY_BYTES` | `1048576` | deployment | Largest accepted request body. Applied at the ASGI layer, before the body is parsed and before any caller is authenticated. Refused as 413 `request_body_too_large`. |
| `MIZAN_RATE_LIMITS_PER_MINUTE` | `60,120,240,480` | deployment | Per-replica token-bucket capacities for LOW, MEDIUM, HIGH and CRITICAL, shared as policy across but independently enforced for each protected route class. Exactly four positive, strictly increasing integers are required. Exhaustion is 429 `rate_limit_exceeded`; configured values and refusals are visible on `/metrics`. |
| `MIZAN_EVALUATOR_BUILD` | `development` | deployment | Recorded in every ADR_Record's `evaluator.build`. Production refuses the `development` placeholder: an unpinned evaluator makes the record unreplayable. |
| `MIZAN_EVALUATOR_CONFIGURATION_HASH` | 64 zeros | deployment | Recorded in every ADR_Record's `evaluator.configuration_hash`. Production refuses the all-zero placeholder for the same reason. |
| `MIZAN_EVIDENCE_OBJECT_STORE_ROOT` | `var/evidence` | deployment | Root of the immutable object store the verifier reads. In v1 this is the create-only local WORM analogue; a real WORM target is `MIZAN_AUDIT_ANCHOR_BUCKET`. |
| `MIZAN_HTTP_HOST` | `127.0.0.1` | deployment | Listener address. The default is loopback so an unconfigured process is not reachable. |
| `MIZAN_HTTP_PORT` | `8080` | deployment | Listener port. |
| `MIZAN_TLS_CERTIFICATE_FILE` | *(required in production)* | deployment | Server certificate chain for the in-process mTLS listener (ADR-001 Amendment B). |
| `MIZAN_TLS_PRIVATE_KEY_FILE` | *(required in production)* | deployment | Server private key for the listener. |
| `MIZAN_TLS_CLIENT_CA_FILE` | *(required in production)* | deployment | Client CA trust bundle. The listener sets `CERT_REQUIRED`; without it no execution endpoint can authenticate a workload and every one answers 401. |
| `MIZAN_BENCHMARK_RESULTS_DIR` | `benchmarks/results` | build/test | Destination for machine-readable benchmark artifacts; changing it has no runtime effect. |
| `MIZAN_BENCHMARK_COMMIT_SHA` | checked-out `HEAD` | build/test | Optional assertion only: when set it must exactly equal `HEAD`; it cannot relabel a run. Artifacts also record `worktree_clean`, and provenance validation rejects dirty runs or SHAs that do not resolve to commits in this repository. |
| `MIZAN_ANCHOR_PROVIDER` | `development-unattested` | deployment | `development-unattested` or `rfc3161`; production requires `rfc3161`. Development anchors are explicitly `none_development`/`unattested`. |
| `MIZAN_ENV` | `development` | deployment | `production` enables mandatory startup custody assertions; production refuses development custody or any `local://` signing reference. |
| `MIZAN_KEY_CUSTODY_MODE` | `development` | deployment | The signing **backend**, enumerated where it is read: `development` (publicly derivable keys, refused in production) or `vault-transit` (HashiCorp Vault Transit, native Ed25519, B-18). Any other value is refused at startup naming the modes that exist. The retired spelling `kms_hsm` was read by nothing — an operator who set it got a process that started and signed with development keys, which is the one outcome the control exists to prevent (B-20). Distinct from a key document's `custody` field, which stays `development-derived` \| `kms` \| `hsm`. |
| `MIZAN_VAULT_ADDR` | *(required for `vault-transit`)* | deployment | Vault base URL. Production requires `https://`: the token is a bearer credential for every key that signs this tenant's evidence, and over plaintext it is readable by anything on the path. |
| `MIZAN_VAULT_TOKEN` | *(empty)* | deployment | Vault token. Prefer `MIZAN_VAULT_TOKEN_FILE` — a token in the environment is a token in anything that dumps the environment into a log. |
| `MIZAN_VAULT_TOKEN_FILE` | *(empty)* | deployment | Path to a file holding the Vault token, as a Kubernetes Secret mount or a Vault Agent sink produces. Trailing whitespace is stripped. An unreadable path is refused rather than treated as absent, which would silently fall back to `MIZAN_VAULT_TOKEN`. |
| `MIZAN_VAULT_NAMESPACE` | *(empty)* | deployment | `X-Vault-Namespace` for Vault Enterprise. |
| `MIZAN_VAULT_CA_CERT` | *(empty)* | deployment | PEM bundle used to verify Vault's TLS certificate. Empty means the system trust store. |
| `MIZAN_EVIDENCE_OBJECT_STORE` | `local` | deployment | Where published evidence is written: `local` (a directory — a development WORM *analogue*, and what the chart's `emptyDir` was) or `s3` (a bucket with Object Lock). **Production requires `s3`**: every record this system signs carries `"retention_class": "regulatory_7y"`, and a directory cannot enforce it (B-21). |
| `MIZAN_AUDIT_ANCHOR_BUCKET` | *(required for `s3`)* | deployment | The Object Lock bucket. Registered in this table since v1.0 and read by nothing until now — one of the twenty-one keys T-109 counts. **Object Lock can only be enabled when a bucket is created**, so a bucket without it cannot be repaired in place and startup refuses it by name rather than writing evidence that claims a retention nothing enforces. |
| `MIZAN_S3_ENDPOINT_URL` | *(empty)* | deployment | Empty for AWS S3; set for an S3-compatible endpoint. Requests use path-style addressing, because an endpoint reached by IP or by a bare service name has no virtual-host DNS for `<bucket>.<host>`. |
| `MIZAN_S3_REGION` | `us-east-1` | deployment | Region used for SigV4 signing. |
| `MIZAN_S3_ACCESS_KEY_ID` / `MIZAN_S3_SECRET_ACCESS_KEY` | *(empty)* | deployment | Static credentials. Empty means the default provider chain (instance role, IRSA, environment), which is preferred wherever it is available. |
| `MIZAN_OBJECT_LOCK_RETENTION_YEARS` | `7` | deployment | Retention applied to every written object in **COMPLIANCE** mode, matching the `regulatory_7y` class the records claim. COMPLIANCE rather than GOVERNANCE deliberately: GOVERNANCE can be bypassed by a principal holding `s3:BypassGovernanceRetention`, which makes retention a policy decision rather than a property of the object — and evidence the operator can delete is evidence the operator can be asked to delete. Below one year is refused. |
| `MIZAN_EVIDENCE_RECEIPT_KEY_REF` | `local://evidence-receipt/dev-1` | deployment | Active `evidence-receipt` signing key; must be distinct from every other role. |
| `MIZAN_EVIDENCE_ANCHOR_KEY_REF` | `local://evidence-anchor/dev-1` | deployment | Active `evidence-anchor` signing key; rotation is additive and never re-signs history. |
| `MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF` | `local://execution-token/dev-1` | deployment | Active `execution-token` signing key. |
| `MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF` | `local://degraded-grant/dev-1` | deployment | Active `degraded-grant` signing key; separate from the degraded WAL encryption key. |

> **Signing key reference grammar.** Under `MIZAN_KEY_CUSTODY_MODE=vault-transit` each of the four
> role references above is `vault://<mount>/<key-name>#v<version>`, and the version is **required**.
> Transit keeps every version of a key for ever and signs with the newest by default, so a reference
> without one would silently change who signs at the operator's next rotation while the exported
> `keys.json` still named the old key — and a corpus that does not verify against its published
> keyset is indistinguishable from a forged one. ADR-004 G.1 makes rotation additive for exactly
> this reason: rotating creates a new version and changes nothing until the reference is moved.
> `scripts/provision_vault.sh` creates the keys and prints the four references with the versions it
> made. Under `development` the references stay `local://<role>/<label>`, whose private material is
> `sha256(key_id)` and is therefore derivable by anyone holding a bundle.

| `MIZAN_ANCHOR_TSA_ENDPOINTS` | *(required in production)* | deployment | Comma-separated RFC 3161 authorities. The request contains only the SHA-256 anchor digest; multiple authorities are supported. |
| `MIZAN_ANCHOR_TSA_TRUST_ANCHORS` | *(required in production)* | deployment | Comma-separated local PEM trust-root paths used by the asynchronous attestation worker to validate each timestamp token before recording `attested`; these roots are operator-supplied and never exported in a bundle. |
| `MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS` | `900` | deployment | Maximum pending age before the evidence breaker opens; pending streams cannot be described as externally anchored. |
| `MIZAN_LOW_RISK_DEGRADED_ALLOW` | `false` | deployment | Master switch for the entire degraded-allow path. False disables it regardless of grants. |
| `Policy.fail_open_allowed` | `false` | policy | Per-policy opt-in; requires the master switch **and** a valid grant (I-21). |
| `DegradedModeGrant.max_duration_seconds` | `3600` | tenant | Ceiling `MIZAN_DEGRADED_GRANT_MAX_SECONDS` = 86400. |
| `MIZAN_DEGRADED_ALLOWED_COMPONENTS` | `risk_engine,policy_cache,record_store` | deployment | The policy engine is never eligible. |
| `MIZAN_DEGRADED_GRANT_ISSUER_REGISTRY` | *(required when degraded mode enabled)* | tenant | Allowlisted issuer IDs, algorithms, and public-key refs; caller-supplied `key_ref` alone conveys no trust. |
| `MIZAN_DEGRADED_GRANT_REVOCATION_MAX_AGE_SECONDS` | `60` | deployment | Maximum staleness of the locally cached revocation set. Staler cache disables degraded-allow. |
| `MIZAN_DEGRADED_WAL_DIR` | *(required when degraded mode enabled)* | deployment | Dedicated encrypted volume; may not share an ephemeral application filesystem. |
| `MIZAN_DEGRADED_WAL_MAX_BYTES` | `1073741824` | deployment | Capacity ceiling. At or above the ceiling, new degraded decisions fail closed. |
| `MIZAN_DEGRADED_WAL_FSYNC_MODE` | `always` | deployment | Production permits only `always`; receipt is issued after fsync. |
| `MIZAN_DEGRADED_WAL_KEY_REF` | *(required when degraded mode enabled)* | deployment | Per-node encryption/signing key in KMS/HSM or sealed workload identity. |
| `MIZAN_DEGRADED_WAL_REPLAY_DEADLINE_SECONDS` | `300` | deployment | Maximum time after record-store recovery to publish and anchor buffered streams. |
| `MIZAN_EXECUTION_TOKEN_DEFAULT_TTL_SECONDS` | `300` | deployment | Overridden by `Tool.execution.token_ttl_seconds`, then `Policy.execution_token_ttl_seconds`. |
| `MIZAN_EXECUTION_TOKEN_ISSUER` | *(required)* | deployment | Exact accepted `iss`; tokens may not select their own trust domain. |
| `MIZAN_EXECUTION_TOKEN_SIGNING_ALGORITHMS` | `EdDSA,ES256` | deployment | Explicit allowlist; `none`, symmetric algorithms, and algorithm/key-type confusion are rejected. |
| `MIZAN_EXECUTION_TOKEN_KEYSET_REF` | *(required)* | deployment | Versioned verification keyset with rotation and revocation metadata. |
| `MIZAN_EXECUTION_TOKEN_CLOCK_SKEW_SECONDS` | `30` | deployment | Maximum accepted NumericDate skew for `iat`/`nbf`/`exp`; larger skew fails closed. |
| `MIZAN_SECURITY_EVENT_POOL_MAX_SIZE` | `2` | deployment | Dedicated connections reserved for rollback-independent replay evidence; never borrowed from the primary execution pool. |
| `MIZAN_SECURITY_EVENT_POOL_TIMEOUT_SECONDS` | `0.25` | deployment | Bounded acquisition wait. Timeout drops and alerts the security event rather than deadlocking execution traffic. |
| `Tool.execution.lease_ttl_seconds` | `900` | tool | Duration of one lease without heartbeat. |
| `Tool.execution.heartbeat_interval_seconds` | `60` | tool | |
| `Tool.execution.max_lease_extensions` | `24` | tool | Bounds total execution time to `lease_ttl × (1 + max_extensions)`. |
| `Tool.binding_profile.unknown_pointer_policy` | `reject` | tool | Unclassified arguments are treated as potentially policy-relevant. |
| `MIZAN_VOLATILE_CONTEXT_PATHS` | `security.session_id, security.device_id, security.source_ip, timestamp, request_id` | deployment | Excluded from `context_hash` so I-9 re-checks do not false-positive on benign drift. Changing this changes evidence semantics → ADR required. |
| `MIZAN_APPROVAL_LEASE_SECONDS` | `900` | deployment | How long a claimed approval task in an external workflow provider stays claimed. |
| `Policy.approval_requirements.rejection_mode` | `veto` | policy | Explicit per policy; no global default beyond this. |
| `escalation.pool_mode` | *(none — must be set)* | policy | V-3: absent value is a validation error, not an implicit `augment`. |
| `escalation.carry_forward_votes` | `false` | policy | Conservative default: escalation re-establishes authority. |
| `escalation.max_epochs` | `2` | policy | Max 5. |
| `MIZAN_AUDIT_HMAC_KEY_REF` | *(required)* | deployment | `KeyRef` for the audit commitment key. Rotated; records cite the key they used. |
| `MIZAN_AUDIT_HMAC_KEY_ROTATION_DAYS` | `90` | deployment | Old keys retained for verification for the retention period. |
| `MIZAN_AUDIT_ANCHOR_BUCKET` | *(required)* | deployment | WORM target (S3 Object Lock / equivalent / on-prem file target). |
| `MIZAN_AUDIT_ANCHOR_INTERVAL_SECONDS` | `300` | deployment | Also anchored every `MIZAN_AUDIT_ANCHOR_INTERVAL_RECORDS` = 10000, whichever first. |
| `MIZAN_HASH_VERIFY_CHECKPOINT_INTERVAL` | `1000` | deployment | Records per verification checkpoint; keeps `/v1/audit/verify` O(range). |
| `MIZAN_CHAIN_SHARDS_PER_TENANT` | `4` | tenant | Stream sharding for sequencer throughput. Raising it is additive (new streams, new anchors); lowering it is forbidden. |
| `MIZAN_REDACTION_EVIDENCE_RETENTION_DAYS` | `30` | tenant | Lifetime of encrypted pre-redaction evidence under legal hold. |
| `MIZAN_DLP_FAIL_MODE` | `reject_write` | deployment | On `scan_failed`: reject the audit write (I-19). `log_only` is not a permitted value in production. |
| `MIZAN_EXTERNAL_PAYLOAD_MAX_BYTES` | `262144` | deployment | Envelope ceiling; hard max 1048576. |
| `MIZAN_EXTERNAL_PAYLOAD_MAX_DECOMPRESSED_BYTES` | `1048576` | deployment | Checked while streaming decompression, before JSON parsing. |
| `MIZAN_EXTERNAL_PAYLOAD_MAX_DEPTH` | `32` | deployment | Parser nesting limit; breach is a controlled tool error. |
| `MIZAN_EXTERNAL_PAYLOAD_MAX_KEYS` | `4096` | deployment | Total keys across the parsed document, not merely top-level keys. |
| `MIZAN_EXTERNAL_ADAPTER_TIMEOUT_MS` | `2000` | deployment | Adapter breach → controlled tool error (I-17). |
| `MIZAN_OUTBOX_DRAIN_INTERVAL_MS` | `250` | deployment | `mizan-drain-outbox` tick interval. A saturated batch is drained again immediately rather than waiting out the interval. |
| `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS` | `5` | deployment | Non-financial asynchronous publication SLO; breach opens the evidence breaker. Financial writes always require a receipt before redemption (I-25). Quarantined rows are excluded from the measurement and raise `outbox_poisoned` instead, so one stuck row cannot hold this alarm permanently open. |
| `MIZAN_AUDIT_ANCHOR_INTERVAL_RECORDS` | `10000` | deployment | Records published per stream before an anchor is due, whichever comes first with `MIZAN_AUDIT_ANCHOR_INTERVAL_SECONDS`. |
| `MIZAN_OUTBOX_BATCH_LIMIT` | `100` | deployment | Rows per drain batch. Bounds the size of one published evidence segment. |
| `MIZAN_OUTBOX_MAX_ATTEMPTS` | `5` | deployment | Failed publication attempts before a row is quarantined: excluded from the batch head and from the lag measurement, never deleted, and reported through the evidence breaker. |
| `MIZAN_EXPIRY_SWEEP_INTERVAL_SECONDS` | `30` | deployment | Cadence of the expiry sweep that reaches `EXPIRED` and `LEASE_EXPIRED` at rest. Each candidate is re-checked under a row lock; a person who acts between scan and lock always wins. |
| `MIZAN_APPROVAL_EPOCH_EXPIRY` | `enforced` | deployment | Whether an unanswered approval epoch expires by itself — a money-movement policy, not a tuning knob, and both answers are implemented. `enforced`: the sweeper closes an elapsed epoch as `EXPIRED`, emits `mizan.approval.expired`, and the vote route refuses a late vote with 409 `approval_epoch_expired` — an approval nobody answered is a refusal. `advisory`: nothing is written at rest, an elapsed epoch stays `OPEN`, and a late vote is **accepted** — a deployment choosing this says a human decides every payment and no clock may decide one for them. `expires_at` is recorded and the overdue count is reported under both; the difference is who acts on it. Refusing the late vote while never expiring the epoch would leave an approval that is undecidable by anyone, so the setting reaches the request path and the sweeper together or not at all. |
| `MIZAN_DRAIN_TENANTS` | *(required for `mizan-drain-outbox`)* | deployment | Comma-separated tenants the drainer serves, or `--tenant-id` repeated. Tenants are **not** discovered: `mizan.tenants` carries FORCE ROW LEVEL SECURITY keyed on the current tenant, so enumeration would require crossing the isolation boundary of ADR-005. A tenant absent from this list is never published and never swept. |
| `MIZAN_LOG_LEVEL` | `INFO` | deployment | Root log level for `mizan-control-plane` and `mizan-drain-outbox`. |
| `MIZAN_LOG_FORMAT` | `json` | deployment | `json` or `text`. `json` emits one object per event carrying `request_id`, `tenant_id`, `trace_id`, `span_id` and `decision_id` from the ambient request context. Any other value is refused at startup. |
| `MIZAN_METRICS_PORT` | `0` (off) | deployment | Port for the private Prometheus listener. Metrics are served on their own listener and never on the API: the API authenticates a *tenant*, and process metrics are cross-tenant, so exposing them behind a tenant credential would either leak across tenants or invent a new authority class. |
| `MIZAN_METRICS_HOST` | `127.0.0.1` | deployment | Bind address for that listener. It is unauthenticated and publishes per-tenant decision volumes, publication lag and breaker state; binding it off-loopback logs a warning naming exactly that. |
| `MIZAN_OTEL_EXPORTER_OTLP_ENDPOINT` | *(empty)* | deployment | OTLP/HTTP traces endpoint. Empty means propagate-only: `traceparent` is still continued and still recorded in every ADR_Record (ADR-004 G.22). Set without the `otel` extra installed, startup is **refused** — a process that reports itself ready and exports nothing is the failure found during the incident. |
| `MIZAN_OTEL_SERVICE_NAME` | `mizan-control-plane` | deployment | `service.name` on exported spans. |

### 8.1 MCP Governance Gateway (`mizan-mcp-gateway`)

A client-side component, configured by one TOML file (`integrations/mcp/example.toml`) with an environment fallback for each identity key. It sets nothing on the control plane and can relax no server default: everything below only decides what the gateway *asks*, and the registry's answer always wins.

| Key | Default | Scope | Notes |
|---|---|---|---|
| `[upstream].command` / `.args` / `.env` | *(command required)* | gateway | The MCP tool server this process governs. Env replaces the child's environment when present. |
| `[mizan].url` (`MIZAN_API_URL`) | *(required)* | gateway | Control plane base URL. |
| `[mizan].agent_id` (`MIZAN_AGENT_ID`) | *(required)* | gateway | The registered agent the gateway calls as. |
| `[mizan].agent_token` (`MIZAN_AGENT_TOKEN`) | *(required)* | gateway | Identity token; sent on every call, never logged. The tenant is read from it, never configured (I-3). |
| `[mizan].agent_version` | `1.0.0` | gateway | Must equal the registered agent version or every authorization is `422`. |
| `[mizan].operator_token` (`MIZAN_OPERATOR_TOKEN`) | *(none)* | gateway | Human operator credential, required only for `register_unknown_tools`. Registry writes are closed to agent identities (ADR-001 Amendment E). |
| `[mizan].ca_file` (`MIZAN_CA_FILE`) | *(system trust)* | gateway | Trust roots for the control plane's server certificate. |
| `[mizan].client_certificate_file` / `client_key_file` | *(none)* | gateway | The gateway's own workload certificate. Required with `executor_spiffe_id` over `https`: the authorized executor is read off the verified peer certificate, never off the body (ADR-001 Amendment B). Startup refuses the combination rather than failing at the first high-risk call. |
| `[mizan].executor_spiffe_id` (`MIZAN_EXECUTOR_SPIFFE_ID`) | *(none)* | gateway | When set, the gateway is the ADR-008 executor: it redeems the token, holds the lease, and closes it. When unset it governs and records but does not bind execution, and says so in the result. |
| `[mizan].principal_id` / `principal_type` / `principal_auth_strength` | `prn_mcp-client` / `application` / `federated` | gateway | Who the call is on behalf of when the client does not name an end user. |
| `[mizan].approval_timeout_seconds` | `900` | gateway | How long a call waits for a human before returning `approval_pending`. Giving up cancels nothing: the approval stays open and the work stays paused. |
| `[mizan].approval_poll_seconds` | `3` | gateway | Approval poll interval. |
| `[mizan].execution_binding_retry_seconds` | `15` | gateway | How long an executor keeps waiting on `immutable_receipt_missing` / `approval_receipt_missing` / `receipt_verifier_unavailable`. Publication is asynchronous by design (ADR-004), so arriving early is not being refused. Every other refusal is final on the first answer. |
| `[mizan].register_unknown_tools` | `false` | gateway | Register upstream tools the registry has never seen, under the operator credential. Existing tools are never overwritten. |
| `[mizan].tool_id_prefix` | `tool_` | gateway | `read_portfolio` → `tool_read-portfolio`. |
| `[defaults]` / `[tools.<name>]` `risk_tier` | `HIGH` | gateway | A *floor request* only. An unclassified tool is not a low-risk tool, and the registry's floor always wins. |
| `[defaults]` / `[tools.<name>]` `bound_pointers` | *(empty)* | gateway | Empty means bind every top-level argument in the tool's own input schema: an argument nobody classified may be the one that decides whether the call is safe. |

### 8.1 MCP Governance Gateway (`mizan-mcp-gateway`)

A client-side component, configured by one TOML file (`integrations/mcp/example.toml`) with an environment fallback for each identity key. It sets nothing on the control plane and can relax no server default: everything below only decides what the gateway *asks*, and the registry's answer always wins.

| Key | Default | Scope | Notes |
|---|---|---|---|
| `[upstream].command` / `.args` / `.env` | *(command required)* | gateway | The MCP tool server this process governs. Env replaces the child's environment when present. |
| `[mizan].url` (`MIZAN_API_URL`) | *(required)* | gateway | Control plane base URL. |
| `[mizan].agent_id` (`MIZAN_AGENT_ID`) | *(required)* | gateway | The registered agent the gateway calls as. |
| `[mizan].agent_token` (`MIZAN_AGENT_TOKEN`) | *(required)* | gateway | Identity token; sent on every call, never logged. The tenant is read from it, never configured (I-3). |
| `[mizan].agent_version` | `1.0.0` | gateway | Must equal the registered agent version or every authorization is `422`. |
| `[mizan].operator_token` (`MIZAN_OPERATOR_TOKEN`) | *(none)* | gateway | Human operator credential, required only for `register_unknown_tools`. Registry writes are closed to agent identities (ADR-001 Amendment E). |
| `[mizan].ca_file` (`MIZAN_CA_FILE`) | *(system trust)* | gateway | Trust roots for the control plane's server certificate. |
| `[mizan].client_certificate_file` / `client_key_file` | *(none)* | gateway | The gateway's own workload certificate. Required with `executor_spiffe_id` over `https`: the authorized executor is read off the verified peer certificate, never off the body (ADR-001 Amendment B). Startup refuses the combination rather than failing at the first high-risk call. |
| `[mizan].executor_spiffe_id` (`MIZAN_EXECUTOR_SPIFFE_ID`) | *(none)* | gateway | When set, the gateway is the ADR-008 executor: it redeems the token, holds the lease, and closes it. When unset it governs and records but does not bind execution, and says so in the result. |
| `[mizan].principal_id` / `principal_type` / `principal_auth_strength` | `prn_mcp-client` / `application` / `federated` | gateway | Who the call is on behalf of when the client does not name an end user. |
| `[mizan].approval_timeout_seconds` | `900` | gateway | How long a call waits for a human before returning `approval_pending`. Giving up cancels nothing: the approval stays open and the work stays paused. |
| `[mizan].approval_poll_seconds` | `3` | gateway | Approval poll interval. |
| `[mizan].execution_binding_retry_seconds` | `15` | gateway | How long an executor keeps waiting on `immutable_receipt_missing` / `approval_receipt_missing` / `receipt_verifier_unavailable`. Publication is asynchronous by design (ADR-004), so arriving early is not being refused. Every other refusal is final on the first answer. |
| `[mizan].register_unknown_tools` | `false` | gateway | Register upstream tools the registry has never seen, under the operator credential. Existing tools are never overwritten. |
| `[mizan].tool_id_prefix` | `tool_` | gateway | `read_portfolio` → `tool_read-portfolio`. |
| `[defaults]` / `[tools.<name>]` `risk_tier` | `HIGH` | gateway | A *floor request* only. An unclassified tool is not a low-risk tool, and the registry's floor always wins. |
| `[defaults]` / `[tools.<name>]` `bound_pointers` | *(empty)* | gateway | Empty means bind every top-level argument in the tool's own input schema: an argument nobody classified may be the one that decides whether the call is safe. |

---

## 9. Server-Side Validation Rules (V-rules)

Cross-field constraints JSON Schema cannot express. Each is contract, each gets a named test.

| # | Rule | Enforced at |
|---|---|---|
| V-1 | `Policy.approver ≠ Policy.author` whenever `status ∈ {APPROVED, ACTIVE, SUPERSEDED}`. | `/v1/policies/{id}/transition` |
| V-2 | `approval_requirements.quorum ≤ |eligible approvers|`, and when `distinct_roles_required`, `quorum ≤ |distinct control domains among eligible approvers|`. Unsatisfiable quorum is rejected at authoring time, not discovered at approval time. | policy create/transition + epoch open |
| V-3 | `escalation.pool_mode` and `escalation.carry_forward_votes` must be explicitly present whenever `escalation` is non-null. | policy create |
| V-4 | `rejection_quorum_count` non-null iff `rejection_mode = rejection_quorum`, and `≤ |eligible approvers|`. | policy create |
| V-5 | Every vote in an epoch with `kind = override` carries a non-empty `justification`. | vote cast |
| V-6 | An explicitly empty selector array in `applies_to` matches nothing (fail-closed reading); a wildcard is expressed by omitting the selector. Authoring UI must make this visible. | policy compile |
| V-7 | `resource.data_classification` may be raised above the registry value by the caller, never lowered; `resource.resource_owner` must equal the registry value unless the tool declares multi-owner scope. | §3.1 enrichment |
| V-8 | `Tool.binding_profile.bound_pointers ∩ volatile_pointers = ∅`, and `bound_pointers` is non-empty. | tool register / profile publish |
| V-9 | An `EvaluationContext.tool.binding_profile.profile_version` must exist and be published; profiles are immutable once published. | §3.1 enrichment |
| V-10 | `delegation_chain[-1] == agent.id` and `delegation_chain[0]` is a root agent (`parent_agent_id = null`). | §3.1 enrichment |
| V-11 | Sequence allocation and record insert occur in one transaction; the chain-head row is locked, not a sequence object (I-20). | chain writer |
| V-12 | An audit write whose `redaction.dlp.status = scan_failed` is rejected when `MIZAN_DLP_FAIL_MODE = reject_write` (production default). | audit writer |
| V-13 | Token redemption CASes `jti` from unconsumed → consumed in the same transaction that creates the lease; a repeated `idempotency_key` returns the existing lease rather than creating a second one. | `/v1/actions/{id}/execute` |
| V-14 | Escalation/override close-and-open is a single transaction; a vote committing against the closed epoch afterwards returns 409 with the current epoch number. | `/v1/approvals/{id}/escalate|override` |
| V-15 | `decision_basis=matched_policy` requires `policies.minItems=1`; `default_deny` and `system_fail_closed` require `decision=DENY` and `policies=[]`; `degraded_grant` requires `degraded.is_degraded=true`, non-null `grant_ref`, and `decision∈{ALLOW,CONSTRAIN,REDACT}`. | ADR writer |
| V-16 | A DegradedModeGrant verifies under an allowlisted tenant issuer key and algorithm; `not_before ≤ now < expires_at ≤ issued_at + max_duration_seconds`; its nonce is unrevoked and unused where the grant is single-use. Caller-carried `key_ref` never establishes trust. | degraded-mode gate |
| V-17 | At token redemption, heartbeat, and completion, authenticated peer SPIFFE ID equals `authorized_executor`; token `iss`, `aud`, algorithm, NumericDate window, agent status, principal, delegation hash, and tenant all match current trusted context. | execution gateway |
| V-18 | External `size_bytes` and `raw_hash` are server-computed over received bytes; compressed and decompressed limits, nesting depth, total-key limit, and JSON parse budget are enforced before envelope construction. Raw payload persistence must match `persistence.disposition`. | external adapter boundary |
| V-19 | DecisionEvent `decision_sequence` allocation and insert are atomic; `previous_event_hash` matches the preceding event, event payload fields are valid for `event_type`, and retries return the existing event rather than creating another. | decision event writer |
| V-20 | For `financial_write`, token redemption requires a valid `immutable_receipt_ref` covering the originating ADR_Record and any deciding approval event. Receipt tenant, stream, record hash, and signature must verify outside the Postgres administrative boundary. | execution gateway |
| V-21 | `ExecutionTokenClaims.authorized_executor` is selected server-side from the tool version's non-empty `execution.executor_spiffe_ids`; callers cannot propose or override it. Redemption uses the same immutable tool/profile version cited by the ADR_Record. | tool registration + token issuer |
| V-22 | An agent PATCH requires a distinct strongly authenticated second approver when the **stored** document or the **submitted** document is a production `HIGH`/`CRITICAL` agent. Evaluating only the submitted side lets one operator remove the protection and change the agent in the same write. The delegation parent edge `create_agent` enforces is re-enforced whenever a PATCH moves `parent_agent_id`. The same authority governs registry creation: `POST /v1/agents`, `/v1/tools`, `/v1/tools/{id}/binding-profile` and `/v1/policies` require a human operator with MFA or hardware authentication — never an agent or service identity — and four eyes for a production `HIGH`/`CRITICAL` object. | `POST`/`PATCH /v1/agents`, `/v1/tools`, `/v1/policies` |
| V-23 | `POST /v1/decisions/{id}/execution-token` is accepted only from the agent principal the ADR_Record names, and issues at most one unconsumed, unexpired token per decision — a repeat request returns the outstanding capability, never a second one. Serialized per decision so concurrent requests cannot both mint. | execution token issuer |
| V-24 | Every identity token carries `kid`; it selects exactly one public key from deployment-pinned `MIZAN_IDENTITY_JWKS`, and the JOSE `alg` must equal that key's allowlisted algorithm. Missing, unknown/retired, duplicate, symmetric, private, or algorithm-confused keys fail closed. A token may never select a JWKS URL or trust root. | identity authentication |
| V-25 | Every database evidence receipt reconciles to exactly one record in its receipt-bound immutable object: signatures and content versions verify, object membership is exact in both directions, and the reconstructed receipt stream is dense. A mismatch is checked by the managed drainer and makes `/health/ready` and `/readyz` return 503. Unpublished outbox rows remain governed by the publication-lag SLO and are not reconciliation mismatches. | outbox drainer + readiness |
| V-26 | Every authorize, approval-mutation and execution-token request that would enter protected evaluation/mutation/minting consumes capacity from a bucket keyed by the authenticated tenant, protected route class and authoritative risk tier. Idempotent replay/reissue returns already-recorded state without consuming capacity. Exhaustion is 429 `rate_limit_exceeded`; limits and refusals are visible on the private metrics listener. | control-plane admission guard |
| V-27 | A dependency-triggered `system_fail_closed` record has `degraded.is_degraded=true`, the named unavailable component, and a null `grant_ref`; a healthy evaluation alone records `is_degraded=false`. `degraded_grant` remains the distinct, grant-backed executable path. | authorization service / ADR writer |

---

## 10. Evidence Pipeline (normative)

The authoritative write path (ADR-004 Amendment A). No component writes to two systems independently.

```text
Authorization transaction (single Postgres txn)
  ├─ decision metadata + ADR_Record row
  ├─ chain-head lock → sequence_number, prev_hash, record_hash
  └─ outbox row(s)
        │
        └─(outbox drain, at-least-once, idempotent consumers)
              ├─► Kafka: ordered, stream-partitioned ADR/audit events   [delivery, NOT evidence]
              └─► immutable object storage: canonical record segments
                    + redaction manifests
                    └─► periodic signed Merkle-root / head-hash anchors  [authoritative evidence corpus]
```

- **Postgres** is the searchable registry, approval/epoch state store, idempotency authority, and query index.
- **Kafka** is delivery infrastructure. It is never cited as the evidence of record, and it is never on the decision path (ADR-003).
- **Object storage** holds the authoritative evidence corpus and the anchors that make tampering detectable *outside the Postgres administrative boundary* — which is what makes I-11 meaningful against a privileged operator.
- Atomic publication is mandatory: outbox + idempotent consumers. A direct dual write to Postgres and Kafka is a spec violation (G8).
- **Publication receipts close the pre-anchor execution gap.** The object-store writer returns a signed receipt binding tenant, stream, sequence, and record hash. `financial_write` redemption requires receipts covering the ADR_Record and the deciding approval DecisionEvent (I-25/V-20). Other actions may proceed asynchronously only while unpublished age remains below `MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS`; exceeding it opens the evidence breaker.
- **Database receipts and immutable objects are reconciled.** After every managed drain cycle and on
  readiness, one shared checker verifies every configured stream's receipt signatures, receipt-bound
  object versions, exact receipt↔record membership, and dense hash chain. A missing, divergent, duplicate,
  or extra object record makes `/health/ready` and `/readyz` return 503. Rows that have not yet acquired a
  receipt are ordinary asynchronous publication and remain governed by the unpublished-age SLO.
- **Anchor sets are dense chained evidence.** Every new signed anchor payload includes `anchor_number`
  (zero-based and monotonic per tenant/stream), `prev_anchor_hash` (SHA-256 over the prior complete signed
  payload, with `"0"*64` at genesis), and `covered_record_count`. Its range begins exactly one sequence
  after the prior anchor, and `covered_record_count = to_sequence - from_sequence + 1`. Allocation and
  insertion occur in one transaction while holding the stream's evidence-chain-head row lock. Verifiers
  reject missing anchor numbers, stale terminal anchors, non-dense ranges, broken prior-anchor hashes, and
  a count that differs from either the declared range or the records actually present. Every anchor ending
  inside an exported range is additionally bound to that sequence's `record_hash`; for a non-genesis range,
  the included anchor ending at `from_sequence - 1` must bind its `head_hash` to the first record's
  `prev_hash`. Unsigned export checkpoints are performance aids, never independent evidence.
- **Evidence export bundle v1.0** is a self-contained directory for one tenant/stream/range containing
  exactly `manifest.json`, `records.json`, `receipts.json`, `anchors.json`, `checkpoints.json`, and
  `keys.json`. The manifest binds every file by SHA-256 and declares the range and current assurance.
  Records are reconstructed from immutable objects referenced by signed receipts, not copied from the
  searchable Postgres document. `scripts/verify_evidence_export.py` verifies the bundle without a database,
  Mizan package, credential, or network, using pinned `rfc8785==0.1.4` and `cryptography==50.0.0` plus the
  OpenSSL 3 CLI for RFC 3161 token validation. Unattested development bundles do not invoke OpenSSL.
  Unless every anchor has a verified external timestamp, successful output must state that the stream cannot withstand a party
  holding both Mizan's database and signing key; it must also disclose pre-chain omission and withheld-final-
  anchor limits.
- **Operator export entry point.** An installed control-plane package exposes `mizan-export-evidence`.
  Operators supply the runtime-role PostgreSQL DSN, immutable object-store root, published public-keyset
  document, tenant, stream, output directory, and optional inclusive sequence bounds. The command reconstructs
  records from receipt-addressed immutable objects and creates the v1.0 directory atomically with respect to
  its new output path; it never accepts private signing material and never reads record documents from the
  searchable PostgreSQL tables. Production deployment must authorize and audit invocation outside this CLI.

**Local development:** do not mock away hash semantics. The contract test set is (a) an in-memory deterministic chain writer for unit tests, (b) golden vectors for RFC 8785 canonicalization and corruption detection, (c) a containerized Postgres/Kafka/object-store integration suite, (d) a generated 100k-record fixture verified via checkpointed parallel ranges in a separate performance profile.
