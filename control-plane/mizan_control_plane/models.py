from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PrincipalInput(StrictModel):
    id: str = Field(pattern=r"^prn_[A-Za-z0-9-]{2,64}$")
    type: Literal["customer", "employee", "relationship_manager", "application", "service_identity"]
    role: str | None = None
    auth_strength: Literal["password", "mfa", "hardware", "federated"]


class AgentInput(StrictModel):
    id: str = Field(pattern=r"^agt_[a-z0-9-]{6,64}$")
    version: str
    parent_agent_id: str | None = None
    delegation_chain: list[str] = Field(min_length=1, max_length=6)


class BindingProfileRef(StrictModel):
    profile_id: str = Field(pattern=r"^bp_[a-z0-9_.-]{3,64}$")
    profile_version: int = Field(ge=1)


class ToolInput(StrictModel):
    id: str = Field(pattern=r"^tool_[a-z0-9_.-]{3,64}$")
    parameters_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    binding_profile: BindingProfileRef
    arguments: dict[str, Any] = Field(max_length=256)


class ActionInput(StrictModel):
    type: Literal[
        "read",
        "write",
        "financial_read",
        "financial_write",
        "communicate",
        "export",
        "delete",
        "delegate",
    ]


class CustomerInput(StrictModel):
    id: str = Field(min_length=1, max_length=128)
    segment: str | None = Field(default=None, max_length=64)


class MoneyInput(StrictModel):
    amount: int
    currency: str = Field(pattern=r"^[A-Z]{3}$")


class BusinessInput(StrictModel):
    transaction_value: MoneyInput | None = None
    customer_consent: bool | None = None
    risk_profile: str | None = Field(default=None, max_length=64)
    channel: str | None = Field(default=None, max_length=64)
    jurisdiction: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    business_process: str | None = Field(default=None, max_length=120)


class SecurityInput(StrictModel):
    session_id: str | None = Field(default=None, max_length=128)
    source_ip: str | None = Field(default=None, max_length=45)
    device_id: str | None = Field(default=None, max_length=128)
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    prior_denials_in_session: int | None = Field(default=None, ge=0)


class MappedInput(StrictModel):
    source: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    projection_id: str | None = Field(default=None, pattern=r"^prj_[a-z0-9_.-]{3,64}$")
    projection_version: int | None = Field(default=None, ge=1)
    raw_envelope_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    fields: dict[str, str | int | float | bool | None] = Field(default_factory=dict, max_length=64)


class ResourceInput(StrictModel):
    id: str
    type: str = Field(max_length=64)
    resource_owner: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    data_classification: Literal["public", "internal", "confidential", "pii", "financial", "secret"]


class EvaluationContext(StrictModel):
    schema_version: Literal["1.2"]
    request_id: UUID
    tenant_id: str | None = Field(default=None, pattern=r"^tnt_[a-z0-9-]{4,64}$")
    principal: PrincipalInput
    agent: AgentInput
    customer: CustomerInput | None = None
    intent: str = Field(max_length=120)
    tool: ToolInput
    action: ActionInput
    resource: ResourceInput
    business: BusinessInput | None = None
    security: SecurityInput | None = None
    mapped: MappedInput | None = None
    environment: Literal["development", "staging", "production"]
    timestamp: datetime


class AuthenticatedIdentity(StrictModel):
    tenant_id: str = Field(pattern=r"^tnt_[a-z0-9-]{4,64}$")
    agent_id: str = Field(pattern=r"^agt_[a-z0-9-]{6,64}$")
    subject: str
    delegation_chain: list[str]


class AuthenticatedPrincipal(StrictModel):
    tenant_id: str = Field(pattern=r"^tnt_[a-z0-9-]{4,64}$")
    principal_id: str = Field(pattern=r"^prn_[A-Za-z0-9-]{2,64}$")
    identity_kind: Literal["human", "agent", "service"]
    auth_strength: Literal["password", "mfa", "hardware", "federated"]
    roles: list[str] = Field(default_factory=list)


class AuthorizationResponse(StrictModel):
    approval: dict[str, Any] | None = None
    decision_id: str
    decision: str
    risk: dict[str, Any]
    policies: list[dict[str, Any]]
    reasons: list[str]
    constraints: dict[str, Any] | None = None
    degraded: dict[str, Any]
    approval: dict[str, Any] | None = None
    execution_token: str | None = None


class RegistryAgent(StrictModel):
    tenant_id: str
    agent_id: str
    version: str
    lifecycle_state: str
    permitted_tools: set[str]
    parent_agent_id: str | None = None
    allowed_agent_ids: set[str] = Field(default_factory=set)
    max_delegation_depth: int = Field(default=0, ge=0, le=5)


class RegistryTool(StrictModel):
    tenant_id: str
    tool_id: str
    risk_tier: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    resource_owner: str
    data_classification: Literal["public", "internal", "confidential", "pii", "financial", "secret"]
    profile_id: str
    profile_version: int
    bound_pointers: list[str]
    volatile_pointers: list[str]
    executor_spiffe_ids: list[str]


class PolicyMatch(StrictModel):
    policy_id: str
    version: int
    content_hash: str
    decision: str
    priority: int
    constraints: dict[str, Any] | None = None
    approval_requirements: dict[str, Any] | None = None


class PersistedDecision(StrictModel):
    decision_id: str
    request_id: UUID
    response: AuthorizationResponse
    context_hash: str
    created_at: datetime


class AuditVerifyRequest(StrictModel):
    stream_id: str
    from_sequence: int | None = Field(default=None, ge=0)
    to_sequence: int | None = Field(default=None, ge=0)
    verify_anchors: bool = True


class AgentPatchRequest(StrictModel):
    document: dict[str, Any]


class BindingProfilePublishRequest(StrictModel):
    binding_profile: dict[str, Any]


class PolicySimulationRequest(StrictModel):
    context: EvaluationContext
    version: int | None = Field(default=None, ge=1)


class PolicyTransitionRequest(StrictModel):
    version: int = Field(ge=1)
    target_status: Literal["TESTED", "APPROVED", "ACTIVE", "SUPERSEDED", "RETIRED"]


class ExecutionTokenRequest(StrictModel):
    executor_spiffe_id: str | None = Field(
        default=None,
        max_length=265,
        pattern=r"^spiffe://[A-Za-z0-9._/-]+$",
        description="One of the tool version's registered executors. Never a new one (V-21).",
    )


class ApprovalVoteRequest(StrictModel):
    vote: Literal["APPROVE", "REJECT", "ABSTAIN"]
    epoch_number: int = Field(ge=1)
    role_claim: str | None = None
    justification: str | None = Field(default=None, max_length=2000)
    comment: str | None = Field(default=None, max_length=2000)


class ExecuteRequest(StrictModel):
    execution_token: str
    arguments: dict[str, Any] = Field(max_length=256)
    idempotency_key: str | None = Field(default=None, max_length=128)


class ExecutionCompleteRequest(StrictModel):
    result_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    failure_code: str | None = Field(default=None, max_length=120)
