from __future__ import annotations

from typing import Protocol

from .models import EvaluationContext, PersistedDecision, PolicyMatch, RegistryAgent, RegistryTool


class AuthorizationRepository(Protocol):
    def get_agent(self, tenant_id: str, agent_id: str) -> RegistryAgent | None: ...
    def get_tool(self, tenant_id: str, tool_id: str) -> RegistryTool | None: ...
    def matching_policies(
        self, tenant_id: str, context: EvaluationContext, risk_level: str | None = None
    ) -> list[PolicyMatch]: ...
    def find_decision_by_request(
        self, tenant_id: str, request_id: str
    ) -> PersistedDecision | None: ...
    def persist_decision(self, decision: PersistedDecision, adr_document: dict) -> None: ...


class RiskProvider(Protocol):
    def evaluate(self, context: EvaluationContext, floor: str) -> dict: ...
