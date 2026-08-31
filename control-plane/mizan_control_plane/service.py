from __future__ import annotations

import copy
import hashlib
import logging
from collections import Counter
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import rfc8785
from psycopg import Error as PostgresError
from psycopg.errors import UniqueViolation

from .canonical import binding_hash, canonical_hash, validate_binding_arguments
from .models import (
    AuthenticatedIdentity,
    AuthorizationResponse,
    EvaluationContext,
    PersistedDecision,
    PolicyMatch,
)
from .observability import Metrics, TraceContext, annotate, current_trace
from .policy_engine import PolicyCompileError
from .ports import (
    AuthorizationRepository,
    DuplicateRequestIdError,
    EvidenceWriteError,
    RiskProvider,
)
from .problems import Problem
from .rate_limits import RateLimiter

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
CLASSIFICATION_ORDER = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "pii": 3,
    "financial": 4,
    "secret": 5,
}
DECISION_ORDER = {
    "ALLOW": 0,
    "REDACT": 1,
    "CONSTRAIN": 1,
    "REQUIRE_APPROVAL": 2,
    "ESCALATE": 3,
    "DENY": 4,
}
LOGGER = logging.getLogger(__name__)
EXPECTED_EVIDENCE_ERRORS = (EvidenceWriteError, PostgresError)
# PolicyCompileError is a ValueError raised inside the shipped evaluator, not a RuntimeError:
# SPEC §5.1 requires policy-engine failure to reach system_fail_closed, never an uncaught 500.
POLICY_ENGINE_ERRORS = (RuntimeError, PolicyCompileError)


class AuthorizationService:
    def __init__(
        self,
        repository: AuthorizationRepository,
        risk_provider: RiskProvider,
        evaluator_build: str,
        configuration_hash: str,
        metrics: Metrics | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.repository = repository
        self.risk_provider = risk_provider
        self.evaluator_build = evaluator_build
        self.configuration_hash = configuration_hash
        self.failure_counters: Counter[str] = Counter()
        self.metrics = metrics or Metrics()
        self.rate_limiter = rate_limiter

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
        self._validate_delegation(identity.tenant_id, context, agent)

        tool = self.repository.get_tool(identity.tenant_id, context.tool.id)
        if not tool or context.tool.id not in agent.permitted_tools:
            raise Problem(
                422, "tool_not_permitted", "Tool is unknown or not permitted for this agent"
            )
        if (
            context.tool.binding_profile.profile_id != tool.profile_id
            or context.tool.binding_profile.profile_version != tool.profile_version
        ):
            raise Problem(
                422, "binding_profile_unknown", "Binding profile is not the active tool profile"
            )
        if not tool.executor_spiffe_ids:
            raise Problem(422, "executor_mapping_missing", "Tool has no authorized executor")

        caller_classification = context.resource.data_classification
        if (
            CLASSIFICATION_ORDER[caller_classification]
            < CLASSIFICATION_ORDER[tool.data_classification]
        ):
            raise Problem(
                422, "classification_downgrade", "Caller cannot lower resource classification"
            )
        enriched.resource.resource_owner = tool.resource_owner
        enriched.resource.data_classification = max(
            (caller_classification, tool.data_classification),
            key=CLASSIFICATION_ORDER.__getitem__,
        )
        classification_source = (
            "caller_asserted_upgrade"
            if caller_classification
            and CLASSIFICATION_ORDER[caller_classification]
            > CLASSIFICATION_ORDER[tool.data_classification]
            else "registry"
        )

        validate_binding_arguments(
            context.tool.arguments, tool.bound_pointers, tool.volatile_pointers
        )
        computed_parameters_hash = binding_hash(context.tool.arguments, tool.bound_pointers)
        if computed_parameters_hash != context.tool.parameters_hash:
            raise Problem(
                400, "parameters_hash_mismatch", "Parameters do not match their binding hash"
            )

        context_document = enriched.model_dump(mode="json", exclude={"tenant_id"})
        context_document["tool"].pop("arguments")
        context_hash = canonical_hash(context_document)
        prior = self.repository.find_decision_by_request(
            identity.tenant_id, str(context.request_id)
        )
        if prior:
            if prior.context_hash != context_hash:
                raise Problem(
                    409, "idempotency_conflict", "request_id was used for another context"
                )
            return prior.response

        if self.rate_limiter is not None:
            self.rate_limiter.require(identity.tenant_id, "authorize", tool.risk_tier)

        try:
            risk = self.risk_provider.evaluate(enriched, tool.risk_tier)
        except Exception as exc:
            return self._system_fail_closed(
                identity,
                enriched,
                context_hash,
                context_document,
                classification_source,
                {"level": tool.risk_tier, "floor_source": "degraded_floor"},
                "risk_engine_failure",
                exc,
            )
        if RISK_ORDER[risk["level"]] < RISK_ORDER[tool.risk_tier]:
            risk = {"level": tool.risk_tier, "floor_source": "tool_registry_floor"}

        try:
            matches = self.repository.matching_policies(
                identity.tenant_id, enriched, risk["level"]
            )
        except POLICY_ENGINE_ERRORS as exc:
            return self._system_fail_closed(
                identity,
                enriched,
                context_hash,
                context_document,
                classification_source,
                risk,
                "policy_engine_failure",
                exc,
            )
        terminal_problem: Problem | None = None
        winner: PolicyMatch | None = None
        try:
            decision, reasons, constraints, winner = self._combine(matches)
        except Problem as exc:
            if exc.code != "NOT_IMPLEMENTED":
                raise
            terminal_problem = exc
            decision = "DENY"
            reasons = [f"NOT_IMPLEMENTED: {exc.detail}"]
            constraints = None
        now = datetime.now(UTC)
        decision_id = self._decision_id(identity.tenant_id, context.request_id)
        annotate(tenant_id=identity.tenant_id, decision_id=decision_id)
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
        adr = self._adr_document(
            identity, enriched, response, context_hash, now, classification_source
        )
        persisted = PersistedDecision(
            decision_id=decision_id,
            request_id=context.request_id,
            response=response,
            context_hash=context_hash,
            created_at=now,
        )
        try:
            self.repository.persist_decision(
                persisted,
                adr,
                context_document,
                self._approval_request(decision, winner, enriched),
            )
        except DuplicateRequestIdError:
            return self._recover_concurrent_request(identity.tenant_id, context, context_hash)
        except UniqueViolation as exc:
            if exc.diag.constraint_name not in {
                "adr_records_tenant_id_request_id_key",
                "adr_records_pkey",
            }:
                raise
            return self._recover_concurrent_request(identity.tenant_id, context, context_hash)
        except EXPECTED_EVIDENCE_ERRORS as exc:
            raise Problem(
                503, "evidence_write_failed", "Decision was not returned because evidence failed"
            ) from exc
        # Counted here and not where the document is built: a decision whose evidence did not
        # commit is not a decision, and a metric that disagrees with `adr_records` about how many
        # there are teaches an operator to stop believing the metric.
        self.metrics.decisions.labels(
            identity.tenant_id, response.decision, adr["decision_basis"]
        ).inc()
        if terminal_problem is not None:
            raise terminal_problem
        response.approval = adr["approval"] if adr["approval"]["required"] else None
        return response

    def _recover_concurrent_request(
        self, tenant_id: str, context: EvaluationContext, context_hash: str
    ) -> AuthorizationResponse:
        prior = self.repository.find_decision_by_request(tenant_id, str(context.request_id))
        if prior is None:
            raise Problem(
                409,
                "idempotency_race_unresolved",
                "request_id was committed concurrently but the prior decision is unreadable",
            )
        if prior.context_hash != context_hash:
            raise Problem(409, "idempotency_conflict", "request_id was used for another context")
        return prior.response

    def _system_fail_closed(
        self,
        identity: AuthenticatedIdentity,
        context: EvaluationContext,
        context_hash: str,
        context_document: dict[str, Any],
        classification_source: str,
        risk: dict[str, Any],
        reason: str,
        cause: Exception,
    ) -> AuthorizationResponse:
        now = datetime.now(UTC)
        decision_id = self._decision_id(identity.tenant_id, context.request_id)
        response = AuthorizationResponse(
            decision_id=decision_id,
            decision="DENY",
            risk=risk,
            policies=[],
            reasons=[f"System failed closed: {reason}"],
            constraints=None,
            degraded={"is_degraded": False, "reason": "none", "grant_ref": None},
        )
        adr = self._adr_document(
            identity,
            context,
            response,
            context_hash,
            now,
            classification_source,
            decision_basis="system_fail_closed",
        )
        persisted = PersistedDecision(
            decision_id=decision_id,
            request_id=context.request_id,
            response=response,
            context_hash=context_hash,
            created_at=now,
        )
        try:
            self.repository.persist_decision(persisted, adr, context_document)
        except EXPECTED_EVIDENCE_ERRORS as evidence_error:
            metric = "system_fail_closed_evidence_write_failed"
            self.failure_counters[metric] += 1
            self.metrics.fail_closed.labels(identity.tenant_id, metric).inc()
            LOGGER.critical(
                metric,
                extra={"tenant_id": identity.tenant_id, "decision_id": decision_id, "reason": reason},
                exc_info=evidence_error,
            )
            raise Problem(
                503,
                "fail_closed_evidence_write_failed",
                "Authorization failed closed but its evidence could not be persisted",
            ) from evidence_error
        self.metrics.decisions.labels(identity.tenant_id, response.decision, "system_fail_closed").inc()
        self.metrics.fail_closed.labels(identity.tenant_id, reason).inc()
        raise Problem(
            403,
            "authorization_failed_closed",
            "Authorization was denied because a required evaluator dependency failed",
        ) from cause

    @staticmethod
    def _validate_identity_binding(
        identity: AuthenticatedIdentity, context: EvaluationContext
    ) -> None:
        if context.tenant_id is not None and context.tenant_id != identity.tenant_id:
            raise Problem(403, "tenant_mismatch", "Body tenant differs from authenticated tenant")
        if context.agent.id != identity.agent_id:
            raise Problem(
                403, "agent_identity_mismatch", "Body agent differs from authenticated agent"
            )
        if context.agent.delegation_chain != identity.delegation_chain:
            raise Problem(403, "delegation_mismatch", "Delegation chain differs from token")
        if context.agent.delegation_chain[-1] != context.agent.id:
            raise Problem(403, "invalid_delegation", "Acting agent must terminate delegation chain")

    def _validate_delegation(
        self, tenant_id: str, context: EvaluationContext, acting_agent: Any
    ) -> None:
        chain = context.agent.delegation_chain
        root = self.repository.get_agent(tenant_id, chain[0])
        if not root or root.parent_agent_id is not None:
            raise Problem(
                403, "invalid_delegation_root", "Delegation chain must begin at a root agent"
            )
        if len(chain) > root.max_delegation_depth + 1:
            raise Problem(
                403, "delegation_depth_exceeded", "Delegation chain exceeds root allowance"
            )
        previous = root
        for child_id in chain[1:]:
            child = self.repository.get_agent(tenant_id, child_id)
            if not child or child.parent_agent_id != previous.agent_id:
                raise Problem(
                    403, "invalid_delegation_edge", "Delegation parent edge is not registered"
                )
            if child_id not in previous.allowed_agent_ids:
                raise Problem(403, "delegation_edge_forbidden", "Delegation edge is not allowed")
            if context.tool.id not in previous.permitted_tools:
                raise Problem(403, "delegated_tool_forbidden", "Parent cannot delegate this tool")
            previous = child
        if previous.agent_id != acting_agent.agent_id:
            raise Problem(403, "invalid_delegation", "Registered acting agent differs from chain")

    @staticmethod
    def _combine(
        matches: list[PolicyMatch],
    ) -> tuple[str, list[str], dict | None, PolicyMatch | None]:
        if not matches:
            return "DENY", ["No matching ACTIVE policy; default deny"], None, None
        winner = max(matches, key=lambda p: (p.priority, DECISION_ORDER[p.decision]))
        same_priority = [p for p in matches if p.priority == winner.priority]
        winner = max(same_priority, key=lambda p: DECISION_ORDER[p.decision])
        if winner.decision not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}:
            raise Problem(
                501,
                "NOT_IMPLEMENTED",
                f"Policy outcome {winner.decision} is not implemented in v1",
            )
        return (
            winner.decision,
            [f"Matched {p.policy_id} v{p.version}" for p in matches],
            None,
            winner,
        )

    @staticmethod
    def _approval_request(
        decision: str, winner: PolicyMatch | None, context: EvaluationContext
    ) -> dict[str, Any] | None:
        """The controls a REQUIRE_APPROVAL decision must open its approval with."""
        if decision != "REQUIRE_APPROVAL":
            return None
        requirements = winner.approval_requirements if winner else None
        if not requirements:
            raise Problem(
                422,
                "approval_requirements_missing",
                "A REQUIRE_APPROVAL policy must carry approval_requirements",
            )
        controls = dict(requirements)
        controls.setdefault(
            "distinct_control_domains_required", controls.get("distinct_roles_required", False)
        )
        return {
            # ADR-007: the requesting principal cannot approve its own request.
            "requester_id": context.principal.id,
            "forbidden_approvers": [context.principal.id],
            "controls": controls,
        }

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
        classification_source: str,
        decision_basis: str | None = None,
    ) -> dict:
        decision_basis = decision_basis or (
            "matched_policy" if response.policies else "default_deny"
        )
        trace = current_trace() or TraceContext.begin()
        document = {
            "schema_version": "1.2",
            "decision_id": response.decision_id,
            "tenant_id": identity.tenant_id,
            # SPEC section 2 calls this the W3C traceparent trace-id, and until T-073 it was
            # sha256(request_id): the right shape, stable, and a member of no trace that has ever
            # existed. An investigator holding this record could not open the request that produced
            # it and nothing said so, because a populated well-formed field looks like an answer.
            # Taken from the caller's traceparent now, or minted here when this decision is the
            # start of the trace. Never derived from an identifier that is not one.
            "trace_id": trace.trace_id,
            "span_id": trace.span_id,
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "principal": context.principal.model_dump(mode="json"),
            "agent": context.agent.model_dump(mode="json"),
            "customer": context.customer,
            "intent": context.intent,
            "tool": context.tool.model_dump(mode="json", exclude={"arguments"}),
            "action": context.action.model_dump(mode="json"),
            "resource": context.resource.model_dump(mode="json")
            | {"classification_source": classification_source},
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
            "approval": {
                "required": response.decision == "REQUIRE_APPROVAL",
                "status": "NOT_REQUIRED",
            },
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
