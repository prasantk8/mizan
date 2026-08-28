"""The part of the gateway that is Mizan.

The gateway never decides. Every tool call takes exactly one of four paths, and three of them
produce an ADR_Record:

  ALLOW             → obtain the capability, forward under a lease, record the outcome
  REQUIRE_APPROVAL  → block until an approver acts, then as above
  DENY              → return a refusal that names the reason class
  cannot ask        → refuse. A tool call that could not be submitted for authorization is not
                      performed, because "the control plane was unreachable" is not a permission.

There is no local cache and no fast path. If latency ever forces one, that is a decision for the
founder with a benchmark artifact attached, not an optimisation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from mizan import Decision, MizanClient, Principal, Resource
from mizan.decorator import result_hash
from mizan.errors import ApprovalRejected, ApprovalTimeout, Denied, ProblemError

from .config import GatewayConfig

LOGGER = logging.getLogger("mizan.mcp.gateway")

# Refusals that mean "the evidence publisher has not caught up yet", not "no".
PUBLICATION_PENDING = frozenset(
    {"immutable_receipt_missing", "approval_receipt_missing", "receipt_verifier_unavailable"}
)


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why a call did not happen, in words a model can repeat to a person."""

    reason_class: str
    message: str
    decision_id: str | None = None
    approval_id: str | None = None


@dataclass(frozen=True, slots=True)
class Permission:
    decision: Decision
    lease: dict[str, Any] | None


class ToolGovernor:
    """Turns one MCP `tools/call` into one authorization and one evidence record."""

    def __init__(
        self,
        config: GatewayConfig,
        client: MizanClient,
        *,
        on_pending: Any = None,
    ) -> None:
        self.config = config
        self.client = client
        self.on_pending = on_pending

    def _resource(self, tool_name: str) -> Resource:
        declaration = self.config.declaration(tool_name)
        return Resource(
            id=f"mcp/{tool_name}",
            type=declaration.resource_type,
            resource_owner=declaration.resource_owner,
            data_classification=declaration.data_classification,
        )

    def _principal(self, session_principal: str | None) -> Principal:
        return Principal(
            id=session_principal or self.config.principal_id,
            type=self.config.principal_type,
            auth_strength=self.config.principal_auth_strength,
        )

    def authorize(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        intent: str,
        session_principal: str | None = None,
    ) -> Permission | Refusal:
        declaration = self.config.declaration(tool_name)
        tool_id = self.config.tool_id(tool_name)
        try:
            decision = self.client.decide(
                tool_id=tool_id,
                arguments=arguments,
                action_type=declaration.action_type,
                intent=intent,
                principal=self._principal(session_principal),
                resource=self._resource(tool_name),
                approval_timeout_seconds=self.config.approval_timeout_seconds,
                on_pending=self.on_pending,
            )
        except Denied as denied:
            return Refusal(
                "denied",
                f"Mizan refused this call. {' '.join(denied.reasons)}",
                denied.decision_id,
            )
        except ApprovalRejected as rejected:
            return Refusal(
                "approval_rejected",
                "An approver declined this action, so it was not performed.",
                rejected.decision_id,
                rejected.approval_id,
            )
        except ApprovalTimeout as waiting:
            return Refusal(
                "approval_pending",
                "This action is still waiting for an approver. It has not been performed, and "
                "the request is still open — it can complete later.",
                waiting.decision_id,
                waiting.approval_id,
            )
        except ProblemError as problem:
            return Refusal(
                "authorization_unavailable",
                f"This call could not be authorized ({problem.code}), so it was not performed.",
                None,
            )
        if not self.config.executor_spiffe_id:
            # No executor identity: the gateway governs and records, but cannot bind the
            # execution, and says so rather than pretending the binding happened.
            return Permission(decision=decision, lease=None)
        try:
            lease = self._lease(decision, arguments)
        except ProblemError as problem:
            # An ALLOW that the control plane then refused to issue a capability for is not a
            # permission. Forwarding here would be the one fail-open path in the whole gateway.
            return Refusal(
                "execution_binding_unavailable",
                "Mizan authorized this call but would not issue the capability to execute it "
                f"({problem.code}), so it was not performed.",
                decision.decision_id,
            )
        return Permission(decision=decision, lease=lease)

    def _lease(self, decision: Decision, arguments: dict[str, Any]) -> dict[str, Any]:
        """Take the capability and the lease as the registered executor.

        A financial write may not execute until its ADR_Record and its approval are durably
        published (SPEC §5.4), and publication is asynchronous by design (ADR-004). So an executor
        that arrives before the publisher does is early, not refused — and only these two codes
        are retried. Every other refusal is final on the first answer.
        """
        deadline = time.monotonic() + self.config.execution_binding_retry_seconds
        while True:
            try:
                granted = self.client.execution_token(
                    decision.decision_id, self.config.executor_spiffe_id
                )
                return self.client.execute(
                    decision.decision_id, granted["execution_token"], arguments
                )
            except ProblemError as problem:
                if problem.code not in PUBLICATION_PENDING or time.monotonic() >= deadline:
                    LOGGER.warning(
                        "execution binding refused for %s: %s",
                        decision.decision_id,
                        problem.code,
                    )
                    raise
                time.sleep(0.25)

    def record_outcome(
        self, permission: Permission, value: Any, failure_code: str | None = None
    ) -> None:
        if permission.lease is None:
            return
        try:
            self.client.complete(
                permission.decision.decision_id,
                permission.lease["lease_id"],
                result_hash(value),
                failure_code=failure_code,
            )
        except ProblemError as problem:
            LOGGER.error(
                "outcome for %s was not recorded: %s",
                permission.decision.decision_id,
                problem.code,
            )
