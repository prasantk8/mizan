# Deliberately NOT `from __future__ import annotations`. Route parameters are declared as
# Annotated[..., Depends(local_dependency)] where the dependency is a closure over create_app's
# arguments. Under PEP 563 those annotations are strings that FastAPI resolves against module
# globals, where a closure does not exist: the Depends is lost and the parameter silently becomes
# a required query parameter. See test_app_routes.py.

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .approval_repository import ApprovalRepository
from .auth import TokenVerifier, bearer_token
from .config import Settings
from .evidence import EvidenceRepository, ObjectEvidenceVerifier
from .execution import ExecutionService
from .keys import KEY_ROLES, KeyProvider
from .models import (
    AgentPatchRequest,
    ApprovalVoteRequest,
    AuditVerifyRequest,
    AuthenticatedPrincipal,
    AuthorizationResponse,
    BindingProfilePublishRequest,
    EvaluationContext,
    ExecuteRequest,
    ExecutionCompleteRequest,
    PolicySimulationRequest,
    PolicyTransitionRequest,
)
from .mtls import VerifiedPeerSpiffeMiddleware, require_workload_spiffe
from .problems import Problem, problem_response
from .registry import RegistryRepository
from .repository import PostgresAuthorizationRepository
from .risk import RegistryFloorRiskProvider
from .schema_validation import ContractSchemas
from .service import AuthorizationService

LOGGER = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    evidence_verifier: ObjectEvidenceVerifier | None = None,
    execution_service: ExecutionService | None = None,
    key_provider: KeyProvider | None = None,
) -> FastAPI:
    settings = settings or Settings.from_environment()
    verifier = TokenVerifier(settings.jwt_issuer, settings.jwt_audience, settings.jwt_public_key)
    authorization_repository = PostgresAuthorizationRepository(settings.database_url)
    registry_repository = RegistryRepository(settings.database_url)
    evidence_repository = EvidenceRepository(settings.database_url)
    approval_repository = ApprovalRepository(settings.database_url)
    schemas = ContractSchemas(Path(__file__).resolve().parents[2] / "SPEC_v1.md")
    service = AuthorizationService(
        authorization_repository,
        RegistryFloorRiskProvider(),
        settings.evaluator_build,
        settings.evaluator_configuration_hash,
    )

    @asynccontextmanager
    async def lifespan(instance: FastAPI) -> AsyncIterator[None]:
        yield
        for pool in instance.state.connection_pools:
            try:
                pool.close()
            except Exception:  # a pool that will not close must not mask the others
                LOGGER.exception("connection pool did not close cleanly")

    app = FastAPI(title="Mizan Control Plane API", version="1.3.0", lifespan=lifespan)
    # Every pool opened here is closed on shutdown; a caller that builds more (the execution
    # service opens two) appends them before the server starts.
    app.state.connection_pools = [
        authorization_repository.pool,
        registry_repository.pool,
        evidence_repository.pool,
        approval_repository.pool,
    ]
    app.state.settings = settings
    app.add_middleware(VerifiedPeerSpiffeMiddleware)
    app.add_exception_handler(Problem, problem_response)

    @app.post("/v1/authorize", response_model=AuthorizationResponse)
    def authorize(
        context: EvaluationContext, token: str = Depends(bearer_token)
    ) -> AuthorizationResponse:
        return service.authorize(verifier.verify(token), context)

    def tenant_from_token(token: str = Depends(bearer_token)) -> str:
        return verifier.verify_tenant(token)

    def principal_from_token(token: str = Depends(bearer_token)):
        return verifier.verify_principal(token)

    def workload_spiffe(request: Request) -> str:
        return require_workload_spiffe(request.scope)

    @app.post("/v1/agents", status_code=201)
    def create_agent(
        document: dict[str, Any], tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        schemas.validate("Agent", document)
        return registry_repository.create_agent(tenant_id, document)

    @app.get("/v1/agents")
    def list_agents(
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        page = registry_repository.list(tenant_id, "agents", limit, cursor)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.get("/v1/agents/{agent_id}")
    def get_agent(agent_id: str, tenant_id: str = Depends(tenant_from_token)) -> dict[str, Any]:
        return registry_repository.get(tenant_id, "agents", agent_id)

    @app.patch("/v1/agents/{agent_id}")
    def patch_agent(
        agent_id: str,
        request: AgentPatchRequest,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
        second_approval: Annotated[str | None, Header(alias="X-Mizan-Second-Approval")] = None,
    ) -> dict[str, Any]:
        schemas.validate("Agent", request.document)
        second = None
        if second_approval:
            if not second_approval.startswith("Bearer "):
                raise Problem(
                    401, "invalid_second_approval", "Second approval must be a bearer token"
                )
            second = verifier.verify_principal(second_approval.removeprefix("Bearer ").strip())
            if second.tenant_id != principal.tenant_id:
                raise Problem(403, "tenant_mismatch", "Second approver belongs to another tenant")
        return registry_repository.update_agent(
            principal.tenant_id,
            agent_id,
            request.document,
            principal,
            second,
        )

    @app.post("/v1/tools", status_code=201)
    def create_tool(
        document: dict[str, Any], tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        schemas.validate("Tool", document)
        return registry_repository.create_tool(tenant_id, document)

    @app.get("/v1/tools")
    def list_tools(
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        page = registry_repository.list(tenant_id, "tools", limit, cursor)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.get("/v1/tools/{tool_id}")
    def get_tool(tool_id: str, tenant_id: str = Depends(tenant_from_token)) -> dict[str, Any]:
        return registry_repository.get(tenant_id, "tools", tool_id)

    @app.post("/v1/tools/{tool_id}/binding-profile", status_code=201)
    def publish_binding_profile(
        tool_id: str,
        request: BindingProfilePublishRequest,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        current = registry_repository.get(tenant_id, "tools", tool_id)
        candidate = current | {"binding_profile": request.binding_profile}
        schemas.validate("Tool", candidate)
        return registry_repository.publish_binding_profile(
            tenant_id,
            tool_id,
            request.binding_profile,
        )

    @app.post("/v1/policies", status_code=201)
    def create_policy(
        document: dict[str, Any], tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        schemas.validate("Policy", document)
        return registry_repository.create_policy(tenant_id, document)

    @app.get("/v1/policies")
    def list_policies(
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        page = registry_repository.list(tenant_id, "policies", limit, cursor)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.get("/v1/policies/{policy_id}")
    def get_policy(
        policy_id: str,
        version: int | None = Query(None, ge=1),
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        return registry_repository.get(tenant_id, "policies", policy_id, version)

    @app.post("/v1/policies/{policy_id}/simulate")
    def simulate_policy(
        policy_id: str,
        request: PolicySimulationRequest,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
    ) -> dict[str, Any]:
        if principal.identity_kind != "human" or principal.auth_strength not in {"mfa", "hardware"}:
            raise Problem(
                403, "simulation_auth_insufficient", "Simulation requires strong human auth"
            )
        return registry_repository.simulate_policy(
            principal.tenant_id,
            policy_id,
            request.context,
            principal.principal_id,
            request.version,
        )

    @app.post("/v1/policies/{policy_id}/transition")
    def transition_policy(
        policy_id: str,
        request: PolicyTransitionRequest,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
    ) -> dict[str, Any]:
        updated = registry_repository.transition_policy(
            principal.tenant_id,
            policy_id,
            request.version,
            request.target_status,
            principal,
        )
        schemas.validate("Policy", updated)
        return updated

    @app.post("/v1/audit/verify")
    def verify_audit(
        request: AuditVerifyRequest, tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        if not request.stream_id.startswith(f"{tenant_id}:"):
            raise Problem(403, "tenant_mismatch", "Evidence stream differs from token tenant")
        if evidence_verifier is None:
            raise Problem(
                503, "evidence_verifier_unavailable", "Evidence keyset/store is not configured"
            )
        result = evidence_verifier.verify(
            tenant_id,
            request.stream_id,
            request.from_sequence,
            request.to_sequence,
            request.verify_anchors,
        )
        if not result.valid:
            raise Problem(
                409,
                "evidence_chain_broken",
                f"Sequence {result.first_broken_sequence}: expected {result.expected}, got {result.actual}",
            )
        return {"valid": True, "checked_records": result.checked_records}

    @app.get("/v1/audit/anchors")
    def list_anchors(stream_id: str, tenant_id: str = Depends(tenant_from_token)) -> dict[str, Any]:
        if not stream_id.startswith(f"{tenant_id}:"):
            raise Problem(403, "tenant_mismatch", "Evidence stream differs from token tenant")
        return {"items": evidence_repository.anchors(tenant_id, stream_id)}

    @app.get("/v1/decisions/{decision_id}")
    def get_decision(
        decision_id: str, tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        return evidence_repository.decision(tenant_id, decision_id)

    @app.get("/v1/decisions")
    def search_decisions(
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        agent_id: str | None = None,
        tool_id: str | None = None,
        decision: str | None = None,
        risk: str | None = None,
        principal_id: str | None = None,
        customer_id: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        return evidence_repository.search_decisions(
            tenant_id,
            limit,
            cursor,
            agent_id=agent_id,
            tool_id=tool_id,
            decision=decision,
            risk=risk,
            principal_id=principal_id,
            customer_id=customer_id,
            from_time=from_time,
            to_time=to_time,
        )

    @app.get("/v1/dashboard/summary")
    def dashboard_summary(tenant_id: str = Depends(tenant_from_token)) -> dict[str, int]:
        return evidence_repository.dashboard_summary(tenant_id)

    @app.get("/v1/audit")
    def search_audit(
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = None,
        event_type: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        return evidence_repository.search_audit(tenant_id, limit, cursor, event_type)

    @app.get("/v1/audit/keys")
    def audit_keys(tenant_id: str = Depends(tenant_from_token)) -> dict[str, Any]:
        if key_provider is None:
            raise Problem(503, "key_provider_unavailable", "Signing key provider is not configured")
        return {"items": key_provider.verification_keyset()}

    @app.get("/v1/approvals/{approval_id}")
    def get_approval(
        approval_id: str, tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        return approval_repository.get(tenant_id, approval_id)

    @app.post("/v1/approvals/{approval_id}/votes")
    def cast_approval_vote(
        approval_id: str,
        request: ApprovalVoteRequest,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
    ) -> dict[str, Any]:
        return approval_repository.vote(
            principal.tenant_id,
            approval_id,
            principal,
            request.model_dump(),
        )

    @app.post("/v1/approvals/{approval_id}/escalate")
    def escalate_approval(
        approval_id: str,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
    ) -> dict[str, Any]:
        return approval_repository.escalate(principal.tenant_id, approval_id)

    @app.post("/v1/approvals/{approval_id}/override")
    def override_approval(
        approval_id: str,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
    ) -> dict[str, Any]:
        return approval_repository.override(principal.tenant_id, approval_id, principal)

    @app.post("/v1/approvals/{approval_id}/withdraw")
    def withdraw_approval(
        approval_id: str,
        principal: Annotated[AuthenticatedPrincipal, Depends(principal_from_token)],
    ) -> dict[str, Any]:
        return approval_repository.withdraw(
            principal.tenant_id, approval_id, principal.principal_id
        )

    @app.post("/v1/actions/{decision_id}/execute")
    def execute_action(
        decision_id: str,
        request: ExecuteRequest,
        peer_spiffe: Annotated[str, Depends(workload_spiffe)],
    ) -> dict[str, Any]:
        if execution_service is None:
            raise Problem(
                503, "execution_service_unavailable", "Execution keyset is not configured"
            )
        return execution_service.redeem(
            request.execution_token,
            decision_id,
            peer_spiffe,
            request.arguments,
            request.idempotency_key,
        )

    @app.post("/v1/actions/{decision_id}/lease/{lease_id}/heartbeat")
    def heartbeat_lease(
        decision_id: str,
        lease_id: str,
        tenant_id: Annotated[str, Depends(tenant_from_token)],
        peer_spiffe: Annotated[str, Depends(workload_spiffe)],
    ) -> dict[str, Any]:
        if execution_service is None:
            raise Problem(
                503, "execution_service_unavailable", "Execution keyset is not configured"
            )
        return execution_service.heartbeat(tenant_id, decision_id, lease_id, peer_spiffe)

    @app.post("/v1/actions/{decision_id}/lease/{lease_id}/complete")
    def complete_lease(
        decision_id: str,
        lease_id: str,
        request: ExecutionCompleteRequest,
        tenant_id: Annotated[str, Depends(tenant_from_token)],
        peer_spiffe: Annotated[str, Depends(workload_spiffe)],
    ) -> dict[str, Any]:
        if execution_service is None:
            raise Problem(
                503, "execution_service_unavailable", "Execution keyset is not configured"
            )
        return execution_service.complete(
            tenant_id,
            decision_id,
            lease_id,
            peer_spiffe,
            request.result_hash,
            request.failure_code,
        )

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def ready() -> JSONResponse:
        """Readiness is what this process can actually do, not that it started."""
        checks: dict[str, str] = {}
        try:
            # Bounded: readiness must answer, and a probe that blocks is a probe that lies.
            with authorization_repository.pool.connection(timeout=2.0) as connection:
                connection.execute("SELECT 1")
            checks["database"] = "ok"
        except Exception as exc:
            checks["database"] = f"unavailable: {type(exc).__name__}"
        if key_provider is None:
            checks["signing_keys"] = "absent"
        else:
            try:
                for role in KEY_ROLES:
                    key_provider.active_key(role)
                checks["signing_keys"] = "ok"
            except Exception as exc:
                checks["signing_keys"] = f"unavailable: {type(exc).__name__}"
        checks["evidence_verifier"] = "ok" if evidence_verifier is not None else "absent"
        checks["execution_service"] = "ok" if execution_service is not None else "absent"
        if settings.environment == "production":
            checks["anchor_provider"] = (
                "ok"
                if settings.anchor_provider == "rfc3161"
                and settings.anchor_tsa_endpoints
                and settings.anchor_tsa_trust_anchors
                else "unattested"
            )
            checks["mutual_tls"] = "ok" if settings.mutual_tls_configured else "absent"
        ready_now = all(value == "ok" for value in checks.values())
        return JSONResponse(
            {"status": "ready" if ready_now else "not_ready", "checks": checks},
            status_code=200 if ready_now else 503,
        )

    ui_root = Path(__file__).resolve().parents[2] / "ui"
    if (ui_root / "index.html").exists():
        app.mount("/", StaticFiles(directory=ui_root, html=True), name="operator-ui")

    return app
