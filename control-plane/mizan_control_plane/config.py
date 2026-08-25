from __future__ import annotations

from dataclasses import dataclass
from os import environ


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    jwt_issuer: str
    jwt_audience: str
    jwt_public_key: str
    evaluator_build: str
    evaluator_configuration_hash: str
    chain_shards_per_tenant: int
    security_event_pool_max_size: int
    security_event_pool_timeout_seconds: float

    @classmethod
    def from_environment(cls) -> Settings:
        required = ("MIZAN_DATABASE_URL", "MIZAN_JWT_ISSUER", "MIZAN_JWT_PUBLIC_KEY")
        missing = [name for name in required if not environ.get(name)]
        if missing:
            raise RuntimeError(f"missing required configuration: {', '.join(missing)}")
        return cls(
            database_url=environ["MIZAN_DATABASE_URL"],
            jwt_issuer=environ["MIZAN_JWT_ISSUER"],
            jwt_audience=environ.get("MIZAN_JWT_AUDIENCE", "mizan-control-plane"),
            jwt_public_key=environ["MIZAN_JWT_PUBLIC_KEY"],
            evaluator_build=environ.get("MIZAN_EVALUATOR_BUILD", "development"),
            evaluator_configuration_hash=environ.get(
                "MIZAN_EVALUATOR_CONFIGURATION_HASH", "0" * 64
            ),
            chain_shards_per_tenant=int(environ.get("MIZAN_CHAIN_SHARDS_PER_TENANT", "4")),
            security_event_pool_max_size=int(
                environ.get("MIZAN_SECURITY_EVENT_POOL_MAX_SIZE", "2")
            ),
            security_event_pool_timeout_seconds=float(
                environ.get("MIZAN_SECURITY_EVENT_POOL_TIMEOUT_SECONDS", "0.25")
            ),
        )
