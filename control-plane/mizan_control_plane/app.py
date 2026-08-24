from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Query

from .auth import TokenVerifier, bearer_token
from .config import Settings
from .models import AuthorizationResponse, EvaluationContext
from .problems import Problem, problem_response
from .registry import RegistryRepository
from .repository import PostgresAuthorizationRepository
from .risk import RegistryFloorRiskProvider
from .schema_validation import ContractSchemas
from .service import AuthorizationService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    verifier = TokenVerifier(settings.jwt_issuer, settings.jwt_audience, settings.jwt_public_key)
    authorization_repository = PostgresAuthorizationRepository(settings.database_url)
    registry_repository = RegistryRepository(settings.database_url)
    schemas = ContractSchemas(Path(__file__).resolve().parents[2] / "SPEC_v1.md")
    service = AuthorizationService(
        authorization_repository, RegistryFloorRiskProvider(),
        settings.evaluator_build, settings.evaluator_configuration_hash,
    )
    app = FastAPI(title="Mizan Control Plane API", version="1.1.0")
    app.add_exception_handler(Problem, problem_response)

    @app.post("/v1/authorize", response_model=AuthorizationResponse)
    def authorize(context: EvaluationContext, token: str = Depends(bearer_token)) -> AuthorizationResponse:
        return service.authorize(verifier.verify(token), context)

    def tenant_from_token(token: str = Depends(bearer_token)) -> str:
        return verifier.verify(token).tenant_id

    @app.post("/v1/agents", status_code=201)
    def create_agent(
        document: dict[str, Any], tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        schemas.validate("Agent", document)
        return registry_repository.create_agent(tenant_id, document)

    @app.get("/v1/agents")
    def list_agents(
        limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        page = registry_repository.list(tenant_id, "agents", limit, cursor)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.get("/v1/agents/{agent_id}")
    def get_agent(agent_id: str, tenant_id: str = Depends(tenant_from_token)) -> dict[str, Any]:
        return registry_repository.get(tenant_id, "agents", agent_id)

    @app.post("/v1/tools", status_code=201)
    def create_tool(
        document: dict[str, Any], tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        schemas.validate("Tool", document)
        return registry_repository.create_tool(tenant_id, document)

    @app.get("/v1/tools")
    def list_tools(
        limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        page = registry_repository.list(tenant_id, "tools", limit, cursor)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.get("/v1/tools/{tool_id}")
    def get_tool(tool_id: str, tenant_id: str = Depends(tenant_from_token)) -> dict[str, Any]:
        return registry_repository.get(tenant_id, "tools", tool_id)

    @app.post("/v1/policies", status_code=201)
    def create_policy(
        document: dict[str, Any], tenant_id: str = Depends(tenant_from_token)
    ) -> dict[str, Any]:
        schemas.validate("Policy", document)
        return registry_repository.create_policy(tenant_id, document)

    @app.get("/v1/policies")
    def list_policies(
        limit: int = Query(50, ge=1, le=200), cursor: str | None = None,
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        page = registry_repository.list(tenant_id, "policies", limit, cursor)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.get("/v1/policies/{policy_id}")
    def get_policy(
        policy_id: str, version: int | None = Query(None, ge=1),
        tenant_id: str = Depends(tenant_from_token),
    ) -> dict[str, Any]:
        return registry_repository.get(tenant_id, "policies", policy_id, version)

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    return app
