from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime
from uuid import UUID

import rfc8785

from .canonical import binding_hash, canonical_hash
from .models import (
    AuthenticatedIdentity,
    AuthorizationResponse,
    EvaluationContext,
    PersistedDecision,
    PolicyMatch,
)
from .ports import AuthorizationRepository, RiskProvider
from .problems import Problem

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
CLASSIFICATION_ORDER = {
    "public": 0, "internal": 1, "confidential": 2,
    "pii": 3, "financial": 4, "secret": 5,
}
DECISION_ORDER = {
    "ALLOW": 0, "REDACT": 1, "CONSTRAIN": 1,
    "REQUIRE_APPROVAL": 2, "ESCALATE": 3, "DENY": 4,
}


class AuthorizationService:
    def __init__(
        self,
        repository: AuthorizationRepository,
        risk_provider: RiskProvider,
        evaluator_build: str,
        configuration_hash: str,
    ) -> None:
        self.repository = repository
        self.risk_provider = risk_provider
        self.evaluator_build = evaluator_build
        self.configuration_hash = configuration_hash

    def authorize(
        self, identity: AuthenticatedIdentity, context: EvaluationContext
    ) -> AuthorizationResponse:
        self._validate_identity_binding(identity, context)
        enriched = copy.deepcopy(context)
        agent = self.repository.get_agent(identity.tenant_id, identity.agent_id)
        if not agent or agent.lifecycle_state not in {"ACTIVE", "MONITORED"}:
            raise Problem(403, "agent_not_active", "Agent is absent or not active")
        if agent.version != context.agent.version:
            raise Problem(422, "agent_version_unknown", "Agent version is not registered")

        tool = self.repository.get_tool(identity.tenant_id, context.tool.id)
        if not tool or context.tool.id not in agent.permitted_tools:
            raise Problem(422, "tool_not_permitted", "Tool is unknown or not permitted for this agent")
        if (
            context.tool.binding_profile.profile_id != tool.profile_id
            or context.tool.binding_profile.profile_version != tool.profile_version
        ):
            raise Problem(422, "binding_profile_unknown", "Binding profile is not the active tool profile")
        if not tool.executor_spiffe_ids:
            raise Problem(422, "executor_mapping_missing", "Tool has no authorized executor")

        caller_classification = context.resource.data_classification
        if caller_classification is not None and (
            CLASSIFICATION_ORDER[caller_classification]
            < CLASSIFICATION_ORDER[tool.data_classification]
        ):
            raise Problem(422, "classification_downgrade", "Caller cannot lower resource classification")
        enriched.resource.resource_owner = tool.resource_owner
        enriched.resource.data_classification = max(
            (caller_classification or tool.data_classification, tool.data_classification),
            key=CLASSIFICATION_ORDER.__getitem__,
        )
        enriched.resource.classification_source = (
            "caller_asserted_upgrade"
            if caller_classification
            and CLASSIFICATION_ORDER[caller_classification]
            > CLASSIFICATION_ORDER[tool.data_classification]
            else "registry"
        )

        computed_parameters_hash = binding_hash(context.tool.parameters, tool.bound_pointers)
        if computed_parameters_hash != context.tool.parameters_hash:
            raise Problem(400, "parameters_hash_mismatch", "Parameters do not match their binding hash")

        context_document = enriched.model_dump(mode="json", exclude={"tenant_id"})
        context_hash = canonical_hash(context_document)
        prior = self.repository.find_decision_by_request(identity.tenant_id, str(context.request_id))
        if prior:
            if prior.context_hash != context_hash:
                raise Problem(409, "idempotency_conflict", "request_id was used for another context")
            return prior.response

        try:
            risk = self.risk_provider.evaluate(enriched, tool.risk_tier)
        except Exception as exc:
            raise Problem(503, "risk_engine_unavailable", "Risk evaluation failed closed") from exc
        if RISK_ORDER[risk["level"]] < RISK_ORDER[tool.risk_tier]:
            risk = {"level": tool.risk_tier, "floor_source": "tool_registry_floor"}

        matches = self.repository.matching_policies(identity.tenant_id, enriched)
        decision, reasons, constraints = self._combine(matches)
        now = datetime.now(UTC)
        decision_id = self._decision_id(identity.tenant_id, context.request_id)
        policies = [
            {"policy_id": p.policy_id, "version": p.version, "content_hash": p.content_hash}
            for p in matches
        ]
        response = AuthorizationResponse(
            decision_id=decision_id,
            decision=decision,
            risk=risk,
            policies=policies,
            reasons=reasons,
            constraints=constraints,
            degraded={"is_degraded": False, "reason": "none", "grant_ref": None},
        )
        adr = self._adr_document(identity, enriched, response, context_hash, now)
        persisted = PersistedDecision(
            decision_id=decision_id,
            request_id=context.request_id,
            response=response,
            context_hash=context_hash,
            created_at=now,
        )
        try:
            self.repository.persist_decision(persisted, adr)
        except Exception as exc:
            raise Problem(503, "evidence_write_failed", "Decision was not returned because evidence failed") from exc
        return response

    @staticmethod
    def _validate_identity_binding(
        identity: AuthenticatedIdentity, context: EvaluationContext
    ) -> None:
        if context.tenant_id is not None and context.tenant_id != identity.tenant_id:
            raise Problem(403, "tenant_mismatch", "Body tenant differs from authenticated tenant")
        if context.agent.id != identity.agent_id:
            raise Problem(403, "agent_identity_mismatch", "Body agent differs from authenticated agent")
        if context.agent.delegation_chain != identity.delegation_chain:
            raise Problem(403, "delegation_mismatch", "Delegation chain differs from token")
        if context.agent.delegation_chain[-1] != context.agent.id:
            raise Problem(403, "invalid_delegation", "Acting agent must terminate delegation chain")

    @staticmethod
    def _combine(matches: list[PolicyMatch]) -> tuple[str, list[str], dict | None]:
        if not matches:
            return "DENY", ["No matching ACTIVE policy; default deny"], None
        winner = max(matches, key=lambda p: (p.priority, DECISION_ORDER[p.decision]))
        same_priority = [p for p in matches if p.priority == winner.priority]
        winner = max(same_priority, key=lambda p: DECISION_ORDER[p.decision])
        return winner.decision, [f"Matched {p.policy_id} v{p.version}" for p in matches], winner.constraints

    @staticmethod
    def _decision_id(tenant_id: str, request_id: UUID) -> str:
        digest = hashlib.sha256(f"{tenant_id}:{request_id}".encode()).hexdigest()[:24]
        return f"adr_{digest}"

    def _adr_document(
        self,
        identity: AuthenticatedIdentity,
        context: EvaluationContext,
        response: AuthorizationResponse,
        context_hash: str,
        now: datetime,
    ) -> dict:
        decision_basis = "matched_policy" if response.policies else "default_deny"
        document = {
            "schema_version": "1.2",
            "decision_id": response.decision_id,
            "tenant_id": identity.tenant_id,
            "trace_id": context.environment.get("trace_id", "0" * 32),
            "span_id": context.environment.get("span_id"),
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "principal": context.principal.model_dump(mode="json"),
            "agent": context.agent.model_dump(mode="json"),
            "customer": context.customer,
            "intent": context.intent,
            "tool": context.tool.model_dump(mode="json", exclude={"parameters"}),
            "action": context.action.model_dump(mode="json"),
            "resource": context.resource.model_dump(mode="json"),
            "context_hash": context_hash,
            "risk": response.risk,
            "policies": response.policies,
            "decision": response.decision,
            "decision_basis": decision_basis,
            "evaluator": {
                "build": self.evaluator_build,
                "engine": "walking-skeleton",
                "configuration_hash": self.configuration_hash,
            },
            "reasons": response.reasons,
            "approval": {"required": response.decision == "REQUIRE_APPROVAL", "status": "NOT_REQUIRED"},
            "execution": {"status": "NOT_STARTED"},
            "degraded": response.degraded,
            "security_signals": [],
            "stream_id": f"{identity.tenant_id}:adr:0",
            "sequence_number": 0,
            "prev_hash": "0" * 64,
            "record_hash": "0" * 64,
            "hash_alg": "SHA-256",
            "canonicalization": "RFC8785",
            "anchor_ref": None,
            "immutable_receipt_ref": None,
        }
        hash_input = {key: value for key, value in document.items() if key != "record_hash"}
        document["record_hash"] = hashlib.sha256(rfc8785.dumps(hash_input)).hexdigest()
        return document
