"""The client an agent actually holds.

Three calls carry the whole loop: `authorize` asks, `wait_for_approval` blocks while humans
decide, and `execution_token` collects the capability. `call` composes them, which is what most
callers want.
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from .binding import parameters_hash
from .errors import (
    ApprovalRejected,
    ApprovalTimeout,
    Denied,
    NotImplementedDecision,
    ProblemError,
)

TERMINAL_APPROVAL_STATES = {"APPROVED", "OVERRIDDEN", "REJECTED", "EXPIRED", "WITHDRAWN"}
EXECUTABLE_APPROVAL_STATES = {"APPROVED", "OVERRIDDEN"}
SCHEMA_VERSION = "1.2"


def uuid7() -> UUID:
    """A time-ordered request id (RFC 9562 §5.7).

    Ordering matters here: `request_id` is the idempotency key, and time-ordered keys keep the
    index that enforces uniqueness from fragmenting under load.
    """
    milliseconds = int(time.time() * 1000) & 0xFFFF_FFFF_FFFF
    raw = bytearray(milliseconds.to_bytes(6, "big") + secrets.token_bytes(10))
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return UUID(bytes=bytes(raw))


def rfc3339_now() -> str:
    """Millisecond precision, `Z` suffix — the only shape SPEC §2.0 `Timestamp` accepts."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(UTC).microsecond // 1000:03d}Z"


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    type: str = "employee"
    auth_strength: str = "mfa"
    role: str | None = None

    def document(self) -> dict[str, Any]:
        value = {"id": self.id, "type": self.type, "auth_strength": self.auth_strength}
        if self.role is not None:
            value["role"] = self.role
        return value


@dataclass(frozen=True, slots=True)
class Resource:
    id: str
    type: str
    resource_owner: str
    data_classification: str

    def document(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "resource_owner": self.resource_owner,
            "data_classification": self.data_classification,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    decision_id: str
    decision: str
    risk: dict[str, Any]
    reasons: list[str]
    policies: list[dict[str, Any]]
    approval: dict[str, Any] | None
    document: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def approval_id(self) -> str | None:
        return (self.approval or {}).get("approval_id")


class MizanClient:
    """Talks to one control plane as one agent.

    `token` is the agent's identity token; it is sent on every call and never logged. Nothing in
    this client decides anything — every allow, wait and refusal comes from the control plane.
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        *,
        agent_id: str | None = None,
        agent_version: str = "1.0.0",
        environment: str = "production",
        timeout: float = 15.0,
        transport: httpx.Client | None = None,
    ) -> None:
        self.base_url = (base_url or os.environ.get("MIZAN_API_URL", "")).rstrip("/")
        self.token = token or os.environ.get("MIZAN_AGENT_TOKEN", "")
        if not self.base_url or not self.token:
            raise ValueError(
                "a control plane URL and an agent token are required "
                "(MIZAN_API_URL / MIZAN_AGENT_TOKEN)"
            )
        self.agent_id = agent_id or os.environ.get("MIZAN_AGENT_ID", "")
        self.agent_version = agent_version
        self.environment = environment
        self._client = transport or httpx.Client(base_url=self.base_url, timeout=timeout)
        self._client.headers["Authorization"] = f"Bearer {self.token}"
        self._profiles: dict[str, dict[str, Any]] = {}

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> MizanClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._client.request(method, path, **kwargs)
        if response.status_code >= 400:
            document = _problem(response)
            raise ProblemError(
                response.status_code,
                str(document.get("type", "")).rsplit("/", 1)[-1] or "unknown",
                document.get("detail", response.text),
                document,
            )
        return response.json()

    def binding_profile(self, tool_id: str, *, refresh: bool = False) -> dict[str, Any]:
        """The tool's active binding profile, straight from the registry.

        The client never guesses which arguments are bound: guessing produces a hash the server
        rejects, which is the failure mode this call exists to avoid.
        """
        if refresh or tool_id not in self._profiles:
            self._profiles[tool_id] = self._request("GET", f"/v1/tools/{tool_id}")[
                "binding_profile"
            ]
        return self._profiles[tool_id]

    def build_context(
        self,
        *,
        tool_id: str,
        arguments: dict[str, Any],
        action_type: str,
        intent: str,
        principal: Principal,
        resource: Resource,
        customer: dict[str, Any] | None = None,
        business: dict[str, Any] | None = None,
        security: dict[str, Any] | None = None,
        delegation_chain: list[str] | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        profile = self.binding_profile(tool_id)
        context: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "request_id": request_id or str(uuid7()),
            "principal": principal.document(),
            "agent": {
                "id": self.agent_id,
                "version": self.agent_version,
                "delegation_chain": delegation_chain or [self.agent_id],
            },
            "intent": intent,
            "tool": {
                "id": tool_id,
                "arguments": arguments,
                "parameters_hash": parameters_hash(arguments, profile["bound_pointers"]),
                "binding_profile": {
                    "profile_id": profile["profile_id"],
                    "profile_version": profile["profile_version"],
                },
            },
            "action": {"type": action_type},
            "resource": resource.document(),
            "environment": self.environment,
            "timestamp": rfc3339_now(),
        }
        for name, value in (("customer", customer), ("business", business), ("security", security)):
            if value is not None:
                context[name] = value
        return context

    def authorize(self, context: dict[str, Any]) -> Decision:
        try:
            body = self._request("POST", "/v1/authorize", json=context)
        except ProblemError as problem:
            if problem.status == 501:
                raise NotImplementedDecision(problem.detail) from problem
            raise
        return Decision(
            decision_id=body["decision_id"],
            decision=body["decision"],
            risk=body["risk"],
            reasons=body["reasons"],
            policies=body["policies"],
            approval=body.get("approval"),
            document=body,
        )

    def approval(self, approval_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/approvals/{approval_id}")

    def pending_approvals(self, state: str = "PENDING", limit: int = 50) -> dict[str, Any]:
        return self._request("GET", "/v1/approvals", params={"state": state, "limit": limit})

    def wait_for_approval(
        self,
        decision: Decision,
        *,
        timeout_seconds: float = 900.0,
        poll_seconds: float = 2.0,
        on_poll: Any = None,
    ) -> dict[str, Any]:
        """Block until humans decide, or until the caller gives up.

        Giving up does not cancel anything: the approval stays open and the work stays paused,
        which is the conservative reading and the one an auditor can follow.
        """
        approval_id = decision.approval_id
        if approval_id is None:
            raise ValueError(f"{decision.decision_id} has no approval to wait for")
        deadline = time.monotonic() + timeout_seconds
        while True:
            document = self.approval(approval_id)
            state = document["state"]
            if on_poll is not None:
                on_poll(document)
            if state in EXECUTABLE_APPROVAL_STATES:
                return document
            if state in TERMINAL_APPROVAL_STATES:
                raise ApprovalRejected(decision.decision_id, approval_id, state)
            if time.monotonic() >= deadline:
                raise ApprovalTimeout(decision.decision_id, approval_id, timeout_seconds)
            time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

    def execution_token(
        self, decision_id: str, executor_spiffe_id: str | None = None
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/decisions/{decision_id}/execution-token",
            json={"executor_spiffe_id": executor_spiffe_id},
        )

    def execute(
        self,
        decision_id: str,
        execution_token: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/actions/{decision_id}/execute",
            json={
                "execution_token": execution_token,
                "arguments": arguments,
                "idempotency_key": idempotency_key,
            },
        )

    def complete(
        self,
        decision_id: str,
        lease_id: str,
        result_hash: str,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/v1/actions/{decision_id}/lease/{lease_id}/complete",
            json={"result_hash": result_hash, "failure_code": failure_code},
        )

    def decide(
        self,
        *,
        tool_id: str,
        arguments: dict[str, Any],
        action_type: str,
        intent: str,
        principal: Principal,
        resource: Resource,
        wait_for_approval: bool = True,
        approval_timeout_seconds: float = 900.0,
        on_pending: Any = None,
        **context_fields: Any,
    ) -> Decision:
        """Ask, and wait if a human has to be involved. Raises `Denied` if the answer is no."""
        context = self.build_context(
            tool_id=tool_id,
            arguments=arguments,
            action_type=action_type,
            intent=intent,
            principal=principal,
            resource=resource,
            **context_fields,
        )
        decision = self.authorize(context)
        if decision.decision == "DENY":
            raise Denied(decision.decision_id, decision.reasons)
        if decision.decision == "REQUIRE_APPROVAL":
            if not wait_for_approval:
                return decision
            if on_pending is not None:
                on_pending(decision)
            self.wait_for_approval(decision, timeout_seconds=approval_timeout_seconds)
        return decision


def _problem(response: httpx.Response) -> dict[str, Any]:
    try:
        document = response.json()
    except ValueError:
        return {"detail": response.text}
    return document if isinstance(document, dict) else {"detail": response.text}
