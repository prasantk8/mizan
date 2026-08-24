from __future__ import annotations

from fastapi import Depends, FastAPI

from .auth import TokenVerifier, bearer_token
from .config import Settings
from .models import AuthorizationResponse, EvaluationContext
from .problems import Problem, problem_response
from .repository import PostgresAuthorizationRepository
from .risk import RegistryFloorRiskProvider
from .service import AuthorizationService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    verifier = TokenVerifier(settings.jwt_issuer, settings.jwt_audience, settings.jwt_public_key)
    service = AuthorizationService(
        PostgresAuthorizationRepository(settings.database_url), RegistryFloorRiskProvider(),
        settings.evaluator_build, settings.evaluator_configuration_hash,
    )
    app = FastAPI(title="Mizan Control Plane API", version="1.1.0")
    app.add_exception_handler(Problem, problem_response)

    @app.post("/v1/authorize", response_model=AuthorizationResponse)
    def authorize(context: EvaluationContext, token: str = Depends(bearer_token)) -> AuthorizationResponse:
        return service.authorize(verifier.verify(token), context)

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    return app

