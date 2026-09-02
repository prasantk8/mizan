from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from os import environ
from pathlib import Path

from .auth import IdentityKeySet

RATE_LIMIT_RISK_TIERS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def parse_rate_limits(raw: str) -> tuple[int, int, int, int]:
    """Parse the closed LOW→CRITICAL quota list and reject an inverted shedding order."""
    try:
        values = tuple(int(item.strip()) for item in raw.split(","))
    except ValueError as exc:
        raise RuntimeError(
            "MIZAN_RATE_LIMITS_PER_MINUTE must contain four comma-separated integers"
        ) from exc
    if len(values) != 4 or any(value < 1 for value in values):
        raise RuntimeError(
            "MIZAN_RATE_LIMITS_PER_MINUTE must contain four positive integers for "
            "LOW,MEDIUM,HIGH,CRITICAL"
        )
    if any(left >= right for left, right in pairwise(values)):
        raise RuntimeError(
            "MIZAN_RATE_LIMITS_PER_MINUTE must rise strictly from LOW through CRITICAL"
        )
    return values  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    jwt_issuer: str
    jwt_audience: str
    identity_jwks: str
    evaluator_build: str
    evaluator_configuration_hash: str
    chain_shards_per_tenant: int
    security_event_pool_max_size: int
    security_event_pool_timeout_seconds: float
    environment: str
    key_custody_mode: str
    signing_key_refs: tuple[str, str, str, str]
    audit_commitment_key_ref: str
    anchor_provider: str
    anchor_tsa_endpoints: tuple[str, ...]
    anchor_tsa_trust_anchors: tuple[str, ...]
    anchor_attestation_max_pending_seconds: int
    # Both registered in SPEC section 8 and read by nothing until there was a drain worker to
    # read them -- two of the twenty-one keys T-109 enumerates. An operator who set either got
    # silence, which is the failure that task exists to end.
    evidence_max_unpublished_seconds: int
    outbox_drain_interval_ms: int
    # An identity token is a bearer credential with no revocation path, so its lifetime is the
    # whole of its blast radius. `exp` was required and unbounded (T-112).
    identity_token_max_ttl_seconds: int
    # A body cap is the difference between a rejected request and an allocation the process makes
    # on a stranger's behalf before it has authenticated anyone.
    max_request_body_bytes: int
    evidence_object_store_root: str
    hash_verify_checkpoint_interval: int
    execution_token_issuer: str
    execution_token_clock_skew_seconds: int
    execution_token_default_ttl_seconds: int
    http_host: str
    http_port: int
    tls_certificate_file: str | None
    tls_private_key_file: str | None
    tls_client_ca_file: str | None
    outbox_batch_limit: int = 100
    outbox_max_attempts: int = 5
    audit_anchor_interval_seconds: int = 300
    audit_anchor_interval_records: int = 10000
    expiry_sweep_interval_seconds: float = 30.0
    approval_epoch_expiry: str = "enforced"
    drain_tenants: tuple[str, ...] = ()
    log_level: str = "INFO"
    log_format: str = "json"
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 0
    otel_exporter_endpoint: str = ""
    otel_service_name: str = "mizan-control-plane"
    # Vault Transit (B-18). Defaulted because the development backend needs none of them, and
    # `from_environment` refuses `vault-transit` without an address and a token rather than
    # letting an empty string reach an HTTP client.
    vault_address: str = ""
    vault_token: str = ""
    vault_namespace: str = ""
    vault_ca_certificate: str = ""
    # Evidence durability under B-21. `local` is a directory and is a development WORM *analogue*
    # by its own docstring; `s3` is a bucket whose immutability the storage layer enforces.
    # `MIZAN_AUDIT_ANCHOR_BUCKET` has been registered in SPEC §8 and read by nothing since the
    # spec was written -- one of the twenty-one keys T-109 counts.
    evidence_object_store: str = "local"
    audit_anchor_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_region: str = "us-east-1"
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    object_lock_retention_years: int = 7
    rate_limits_per_minute: tuple[int, int, int, int] = (60, 120, 240, 480)
    # Memtara is a separately operated issuer. Both values are deployment-pinned; request
    # material is never allowed to choose an issuer or a verification URL.
    memtara_trusted_issuer: str = ""
    memtara_jwks_url: str = ""

    @property
    def rate_limit_map(self) -> dict[str, int]:
        return dict(zip(RATE_LIMIT_RISK_TIERS, self.rate_limits_per_minute, strict=True))

    @property
    def metrics_enabled(self) -> bool:
        return self.metrics_port > 0

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def mutual_tls_configured(self) -> bool:
        return bool(
            self.tls_certificate_file and self.tls_private_key_file and self.tls_client_ca_file
        )

    @classmethod
    def from_environment(cls) -> Settings:
        required = ("MIZAN_DATABASE_URL", "MIZAN_JWT_ISSUER", "MIZAN_IDENTITY_JWKS")
        missing = [name for name in required if not environ.get(name)]
        if missing:
            raise RuntimeError(f"missing required configuration: {', '.join(missing)}")
        identity_jwks = environ["MIZAN_IDENTITY_JWKS"]
        try:
            IdentityKeySet(identity_jwks)
        except ValueError as exc:
            raise RuntimeError(f"invalid MIZAN_IDENTITY_JWKS: {exc}") from exc
        environment = environ.get("MIZAN_ENV", "development")
        # Production requirements are collected and reported together rather than raised one at a
        # time. An operator bringing up a first deployment otherwise learns about them serially --
        # fix, restart, next error, restart -- and each restart is a fresh chance to give up. It
        # also stops a newly added check from shadowing every existing one: three production tests
        # broke that way while this file was being written, each asserting a refusal that a newer
        # guard had started firing before.
        production_problems: list[str] = []
        refs = (
            environ.get("MIZAN_EVIDENCE_RECEIPT_KEY_REF", "local://evidence-receipt/dev-1"),
            environ.get("MIZAN_EVIDENCE_ANCHOR_KEY_REF", "local://evidence-anchor/dev-1"),
            environ.get("MIZAN_EXECUTION_TOKEN_SIGNING_KEY_REF", "local://execution-token/dev-1"),
            environ.get("MIZAN_DEGRADED_GRANT_SIGNING_KEY_REF", "local://degraded-grant/dev-1"),
        )
        # The fifth role and the only MAC one (T-054). Registered in `SPEC_v1.md` since the
        # baseline as *(required)* and read by nothing until now -- a fully specified key with no
        # custody, which is TM-001 R-2 and what B-30 ruled on.
        audit_commitment_key_ref = environ.get(
            "MIZAN_AUDIT_HMAC_KEY_REF", "local://audit-commitment/dev-1"
        )
        custody = environ.get("MIZAN_KEY_CUSTODY_MODE", "development")
        # B-20 stamped the vocabulary as `development-derived | kms | hsm` for a *key document*.
        # This setting names the **backend** rather than the custody of one key, and the two were
        # being spelled with the same words in three places (SPEC §8 said `kms_hsm`, `keys.py` said
        # `kms`, `compose.production.yaml` said `kms`). Accepted values are enumerated here so an
        # operator who writes `kms_hsm` is told, at startup, that the control they set is not read.
        if custody not in ("development", "vault-transit"):
            raise RuntimeError(
                f"MIZAN_KEY_CUSTODY_MODE={custody!r} names no built backend. "
                "'development' signs with publicly derivable keys and is refused in production; "
                "'vault-transit' is the one KMS backend that exists (B-18). PKCS#11 is not built."
            )
        vault_address = environ.get("MIZAN_VAULT_ADDR", "")
        vault_namespace = environ.get("MIZAN_VAULT_NAMESPACE", "")
        vault_ca_certificate = environ.get("MIZAN_VAULT_CA_CERT", "")
        vault_token = environ.get("MIZAN_VAULT_TOKEN", "")
        token_file = environ.get("MIZAN_VAULT_TOKEN_FILE", "")
        if token_file:
            # A file, so a Kubernetes Secret or a Vault Agent sink can supply the token without it
            # appearing in a pod spec, a `docker inspect`, or this process's environment -- where
            # anything that dumps `os.environ` into a log would carry it.
            try:
                vault_token = Path(token_file).read_text(encoding="utf-8").strip()
            except OSError as error:
                raise RuntimeError(
                    f"MIZAN_VAULT_TOKEN_FILE={token_file!r} could not be read: {error.strerror}"
                ) from error
        if custody == "vault-transit":
            if not vault_address:
                raise RuntimeError("MIZAN_KEY_CUSTODY_MODE=vault-transit requires MIZAN_VAULT_ADDR")
            if not vault_token:
                raise RuntimeError(
                    "MIZAN_KEY_CUSTODY_MODE=vault-transit requires MIZAN_VAULT_TOKEN or "
                    "MIZAN_VAULT_TOKEN_FILE"
                )
            if environment == "production" and not vault_address.startswith("https://"):
                # The token is a bearer credential for every key that signs this tenant's evidence.
                # Over plaintext it is readable by anything on the path, and the same reasoning
                # already refuses a plaintext TSA endpoint further down.
                production_problems.append("production requires an https:// MIZAN_VAULT_ADDR")
        object_store = environ.get("MIZAN_EVIDENCE_OBJECT_STORE", "local").lower()
        if object_store not in ("local", "s3"):
            raise RuntimeError("MIZAN_EVIDENCE_OBJECT_STORE must be 'local' or 's3'")
        audit_anchor_bucket = environ.get("MIZAN_AUDIT_ANCHOR_BUCKET", "")
        retention_years = int(environ.get("MIZAN_OBJECT_LOCK_RETENTION_YEARS", "7"))
        if object_store == "s3" and not audit_anchor_bucket:
            raise RuntimeError("MIZAN_EVIDENCE_OBJECT_STORE=s3 requires MIZAN_AUDIT_ANCHOR_BUCKET")
        if environment == "production" and object_store != "s3":  # noqa: SIM102
            # `LocalImmutableObjectStore` calls itself a development WORM *analogue* in its own
            # docstring, and every record this system signs carries `"retention_class":
            # "regulatory_7y"`. A directory cannot enforce that, and the chart's `emptyDir` under
            # `replicaCount: 2` actively contradicted it: a rollout destroyed the corpus (B-21).
            production_problems.append(
                "production requires MIZAN_EVIDENCE_OBJECT_STORE=s3 with Object Lock; a directory "
                "cannot enforce the retention every signed record already claims (B-21)"
            )
        anchor_provider = environ.get("MIZAN_ANCHOR_PROVIDER", "development-unattested")
        tsa_endpoints = tuple(
            item for item in environ.get("MIZAN_ANCHOR_TSA_ENDPOINTS", "").split(",") if item
        )
        tsa_trust_anchors = tuple(
            item for item in environ.get("MIZAN_ANCHOR_TSA_TRUST_ANCHORS", "").split(",") if item
        )
        if len(set(refs)) != 4:
            raise RuntimeError("the four signing key roles require distinct key references")
        # The commitment key is held under separate authority (ADR-004 Amendment A), so reusing an
        # evidence signing reference for it is a key-separation failure and not a typo to tolerate.
        if audit_commitment_key_ref in refs:
            raise RuntimeError(
                "MIZAN_AUDIT_HMAC_KEY_REF must not reuse a signing key reference; the audit "
                "commitment key is held under separate authority (ADR-004 G.1, T-054)"
            )
        if environment == "production" and (custody == "development" or any(
            item.startswith("local://") for item in (*refs, audit_commitment_key_ref)
        )):
            production_problems.append(
                "production refuses development custody and local:// signing or commitment keys"
            )
        if environment == "production" and (
            anchor_provider != "rfc3161" or not tsa_endpoints or not tsa_trust_anchors
        ):
            production_problems.append(
                "production requires RFC 3161 anchor provider, TSA endpoint, and trust anchor"
            )
        if environment == "production" and any(
            not endpoint.startswith("https://") for endpoint in tsa_endpoints
        ):
            production_problems.append("production requires HTTPS RFC 3161 TSA endpoints")
        execution_token_issuer = environ.get("MIZAN_EXECUTION_TOKEN_ISSUER", "")
        tls_certificate_file = environ.get("MIZAN_TLS_CERTIFICATE_FILE") or None
        tls_private_key_file = environ.get("MIZAN_TLS_PRIVATE_KEY_FILE") or None
        tls_client_ca_file = environ.get("MIZAN_TLS_CLIENT_CA_FILE") or None
        evaluator_build = environ.get("MIZAN_EVALUATOR_BUILD", "development")
        configuration_hash = environ.get("MIZAN_EVALUATOR_CONFIGURATION_HASH", "0" * 64)
        if environment == "production":
            if environ["MIZAN_JWT_ISSUER"].startswith("urn:mizan:development:"):
                production_problems.append(
                    "production refuses the mizan-dev-token issuer; a demo credential minter is "
                    "not an identity provider"
                )
            if not execution_token_issuer:
                production_problems.append(
                    "production requires MIZAN_EXECUTION_TOKEN_ISSUER; tokens may not select "
                    "their own trust domain"
                )
            if evaluator_build == "development" or configuration_hash == "0" * 64:
                production_problems.append(
                    "production requires a real MIZAN_EVALUATOR_BUILD and "
                    "MIZAN_EVALUATOR_CONFIGURATION_HASH; every ADR_Record pins them as evidence"
                )
            if not (tls_certificate_file and tls_private_key_file and tls_client_ca_file):
                production_problems.append(
                    "production requires MIZAN_TLS_CERTIFICATE_FILE, MIZAN_TLS_PRIVATE_KEY_FILE "
                    "and MIZAN_TLS_CLIENT_CA_FILE; execution endpoints authenticate the workload "
                    "from the verified TLS peer only (ADR-001 Amendment B)"
                )
        log_format = environ.get("MIZAN_LOG_FORMAT", "json").lower()
        if log_format not in ("json", "text"):
            raise RuntimeError("MIZAN_LOG_FORMAT must be 'json' or 'text'")
        # Whether an unanswered approval epoch expires by itself is a money-movement policy, not
        # an implementation detail, so it is a deployment decision and both answers are real.
        # `enforced`: the sweeper closes an elapsed epoch as EXPIRED and emits
        # `mizan.approval.expired`, and the request path refuses a late vote -- an approval nobody
        # answered is a refusal. `advisory`: nothing is ever written at rest, an elapsed epoch
        # stays OPEN and a late vote is accepted, because a deployment that chooses this one is
        # saying a human decides every payment and no clock may decide one for them. The overdue
        # count is reported either way; the difference is who acts on it.
        approval_epoch_expiry = environ.get("MIZAN_APPROVAL_EPOCH_EXPIRY", "enforced").lower()
        if approval_epoch_expiry not in ("enforced", "advisory"):
            raise RuntimeError("MIZAN_APPROVAL_EPOCH_EXPIRY must be 'enforced' or 'advisory'")
        drain_tenants = tuple(
            item.strip() for item in environ.get("MIZAN_DRAIN_TENANTS", "").split(",") if item.strip()
        )
        memtara_trusted_issuer = environ.get("MIZAN_MEMTARA_TRUSTED_ISSUER", "")
        memtara_jwks_url = environ.get("MIZAN_MEMTARA_JWKS_URL", "")
        if bool(memtara_trusted_issuer) != bool(memtara_jwks_url):
            raise RuntimeError(
                "MIZAN_MEMTARA_TRUSTED_ISSUER and MIZAN_MEMTARA_JWKS_URL must be set together"
            )
        if environment == "production" and memtara_jwks_url and not memtara_jwks_url.startswith(
            "https://"
        ):
            production_problems.append("production requires an https:// MIZAN_MEMTARA_JWKS_URL")
        if production_problems:
            raise RuntimeError(
                "production configuration is not usable:\n  - " + "\n  - ".join(production_problems)
            )
        return cls(
            database_url=environ["MIZAN_DATABASE_URL"],
            jwt_issuer=environ["MIZAN_JWT_ISSUER"],
            jwt_audience=environ.get("MIZAN_JWT_AUDIENCE", "mizan-control-plane"),
            identity_jwks=identity_jwks,
            evaluator_build=evaluator_build,
            evaluator_configuration_hash=configuration_hash,
            chain_shards_per_tenant=int(environ.get("MIZAN_CHAIN_SHARDS_PER_TENANT", "4")),
            security_event_pool_max_size=int(
                environ.get("MIZAN_SECURITY_EVENT_POOL_MAX_SIZE", "2")
            ),
            security_event_pool_timeout_seconds=float(
                environ.get("MIZAN_SECURITY_EVENT_POOL_TIMEOUT_SECONDS", "0.25")
            ),
            environment=environment,
            key_custody_mode=custody,
            signing_key_refs=refs,
            audit_commitment_key_ref=audit_commitment_key_ref,
            vault_address=vault_address,
            vault_token=vault_token,
            vault_namespace=vault_namespace,
            vault_ca_certificate=vault_ca_certificate,
            evidence_object_store=object_store,
            audit_anchor_bucket=audit_anchor_bucket,
            s3_endpoint_url=environ.get("MIZAN_S3_ENDPOINT_URL", ""),
            s3_region=environ.get("MIZAN_S3_REGION", "us-east-1"),
            s3_access_key_id=environ.get("MIZAN_S3_ACCESS_KEY_ID", ""),
            s3_secret_access_key=environ.get("MIZAN_S3_SECRET_ACCESS_KEY", ""),
            object_lock_retention_years=retention_years,
            anchor_provider=anchor_provider,
            anchor_tsa_endpoints=tsa_endpoints,
            anchor_tsa_trust_anchors=tsa_trust_anchors,
            anchor_attestation_max_pending_seconds=int(
                environ.get("MIZAN_ANCHOR_ATTESTATION_MAX_PENDING_SECONDS", "900")
            ),
            identity_token_max_ttl_seconds=int(
                environ.get("MIZAN_IDENTITY_TOKEN_MAX_TTL_SECONDS", "3600")
            ),
            max_request_body_bytes=int(
                environ.get("MIZAN_MAX_REQUEST_BODY_BYTES", str(1024 * 1024))
            ),
            evidence_object_store_root=environ.get(
                "MIZAN_EVIDENCE_OBJECT_STORE_ROOT", "var/evidence"
            ),
            hash_verify_checkpoint_interval=int(
                environ.get("MIZAN_HASH_VERIFY_CHECKPOINT_INTERVAL", "1000")
            ),
            execution_token_issuer=execution_token_issuer
            or "urn:mizan:development:execution-token-issuer",
            execution_token_clock_skew_seconds=int(
                environ.get("MIZAN_EXECUTION_TOKEN_CLOCK_SKEW_SECONDS", "30")
            ),
            execution_token_default_ttl_seconds=int(
                environ.get("MIZAN_EXECUTION_TOKEN_DEFAULT_TTL_SECONDS", "300")
            ),
            http_host=environ.get("MIZAN_HTTP_HOST", "127.0.0.1"),
            http_port=int(environ.get("MIZAN_HTTP_PORT", "8080")),
            tls_certificate_file=tls_certificate_file,
            tls_private_key_file=tls_private_key_file,
            tls_client_ca_file=tls_client_ca_file,
            outbox_drain_interval_ms=int(environ.get("MIZAN_OUTBOX_DRAIN_INTERVAL_MS", "250")),
            outbox_batch_limit=int(environ.get("MIZAN_OUTBOX_BATCH_LIMIT", "100")),
            outbox_max_attempts=int(environ.get("MIZAN_OUTBOX_MAX_ATTEMPTS", "5")),
            evidence_max_unpublished_seconds=float(
                environ.get("MIZAN_EVIDENCE_MAX_UNPUBLISHED_SECONDS", "5")
            ),
            audit_anchor_interval_seconds=int(
                environ.get("MIZAN_AUDIT_ANCHOR_INTERVAL_SECONDS", "300")
            ),
            audit_anchor_interval_records=int(
                environ.get("MIZAN_AUDIT_ANCHOR_INTERVAL_RECORDS", "10000")
            ),
            expiry_sweep_interval_seconds=float(
                environ.get("MIZAN_EXPIRY_SWEEP_INTERVAL_SECONDS", "30")
            ),
            drain_tenants=drain_tenants,
            log_level=environ.get("MIZAN_LOG_LEVEL", "INFO"),
            log_format=log_format,
            approval_epoch_expiry=approval_epoch_expiry,
            metrics_host=environ.get("MIZAN_METRICS_HOST", "127.0.0.1"),
            metrics_port=int(environ.get("MIZAN_METRICS_PORT", "0")),
            otel_exporter_endpoint=environ.get("MIZAN_OTEL_EXPORTER_OTLP_ENDPOINT", ""),
            otel_service_name=environ.get("MIZAN_OTEL_SERVICE_NAME", "mizan-control-plane"),
            rate_limits_per_minute=parse_rate_limits(
                environ.get("MIZAN_RATE_LIMITS_PER_MINUTE", "60,120,240,480")
            ),
            memtara_trusted_issuer=memtara_trusted_issuer,
            memtara_jwks_url=memtara_jwks_url,
        )


def resolve_served_tenants(explicit: list[str] | None, environment_key: str) -> list[str]:
    """The tenants a background workload serves -- named, never discovered.

    Every managed workload in this system needs this list and none of them can query it:
    `mizan.tenants` carries `FORCE ROW LEVEL SECURITY` under
    `USING (tenant_id = mizan.current_tenant_id())`, and the schema holds no `SECURITY DEFINER`
    function, so `mizan_app` sees only the tenant it is currently scoped to. Widening that is a
    tenant-isolation decision and therefore H-7 -- escalated as **B-27**, not taken in code.

    **B-27 ratified 2026-09-02 (founder): the served set is named, never discovered.** The isolation
    model is not widened and no `SECURITY DEFINER` function is added. The limit the ruling accepts,
    recorded here rather than only in `WORK_LOG.md` because this is where the next engineer will
    look: a named set holds for a pilot with a known tenant list and **does not scale to self-service
    onboarding**, where a newly created tenant is silently unserved -- its outbox undrained and its
    anchors unattested -- until a human edits a manifest. Nothing in this function detects that. When
    onboarding stops being a human step, this ruling must be reopened before it is relied on.

    It lives here rather than in either worker because the drainer and the attestation runner hit
    the same wall, and a second copy of this reasoning is how two workloads come to resolve
    tenants two subtly different ways.
    """
    named = list(explicit or [])
    if not named:
        named = [
            item.strip() for item in environ.get(environment_key, "").split(",") if item.strip()
        ]
    # Deduplicate while preserving the operator's order, so a cycle is reproducible.
    return list(dict.fromkeys(named))
