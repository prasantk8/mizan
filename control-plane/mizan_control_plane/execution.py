from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import jwt
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool, PoolTimeout

from .canonical import binding_hash, canonical_hash, validate_binding_arguments
from .evidence import append_decision_event_tx
from .keys import SigningKey
from .models import EvaluationContext
from .observability import Metrics
from .ports import RiskProvider
from .problems import Problem
from .rate_limits import RateLimiter
from .risk import RegistryFloorRiskProvider
from .schema_validation import ContractSchemas

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
LOGGER = logging.getLogger(__name__)


def _jti_hash(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def save_lease_tx(connection: Any, tenant_id: str, lease: dict[str, Any]) -> None:
    """Write a lease back on an existing connection.

    Module-level because the expiry sweeper (T-074) reaches `LEASE_EXPIRED` at rest, without an
    executor calling in, and must persist a lease exactly the way a redemption path does. Two
    writers with two shapes for the same row is how a state machine develops a second opinion.
    """
    connection.execute(
        "UPDATE mizan.execution_leases SET state=%s,extensions_used=%s,document=%s,expires_at=%s "
        "WHERE tenant_id=%s AND lease_id=%s",
        (
            lease["state"],
            lease["extensions_used"],
            json.dumps(lease),
            lease["expires_at"],
            tenant_id,
            lease["lease_id"],
        ),
    )


class ExecutionTokenCodec:
    def __init__(
        self,
        issuer: str,
        private_key: Ed25519PrivateKey | None = None,
        public_key: Ed25519PublicKey | None = None,
        clock_skew_seconds: int = 30,
        schemas: ContractSchemas | None = None,
        signing_key: SigningKey | None = None,
    ) -> None:
        if (private_key is None) == (signing_key is None):
            raise ValueError(
                "an execution token codec signs with exactly one of private_key or signing_key"
            )
        self.issuer = issuer
        self.private_key = private_key
        self.signing_key = signing_key
        self.public_key = public_key or (
            private_key.public_key() if private_key is not None else signing_key.public_key()
        )
        self.clock_skew_seconds = clock_skew_seconds
        self.schemas = schemas or ContractSchemas(
            Path(__file__).resolve().parents[2] / "SPEC_v1.md"
        )

    def encode(self, claims: dict[str, Any]) -> str:
        self.schemas.validate("ExecutionTokenClaims", claims)
        if self.private_key is not None:
            return jwt.encode(claims, self.private_key, algorithm="EdDSA", headers={"typ": "JWT"})
        # Custody-agnostic path: a KMS/HSM key never leaves its provider, so the JWS is assembled
        # here and only the signing input crosses the boundary. Verification stays PyJWT's.
        header = _base64url(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
        # RFC 8785, not json.dumps: the claims come back from JSONB in Postgres' key order, and an
        # idempotent re-issue must produce the same bytes as the grant it is repeating.
        payload = _base64url(rfc8785.dumps(claims))
        signature = self.signing_key.sign(f"{header}.{payload}".encode())
        return f"{header}.{payload}.{_base64url(signature)}"

    def decode(self, token: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                issuer=self.issuer,
                audience="mizan-execution-gateway",
                leeway=self.clock_skew_seconds,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "jti"]},
            )
            self.schemas.validate("ExecutionTokenClaims", claims)
            return claims
        except Problem as exc:
            raise Problem(
                403, "execution_token_invalid", "Execution capability claims are malformed"
            ) from exc
        except jwt.PyJWTError as exc:
            raise Problem(
                403, "execution_token_invalid", "Execution capability is invalid or expired"
            ) from exc


class ReceiptGate(Protocol):
    def verify_record_receipt(
        self, tenant_id: str, stream_id: str, sequence_number: int, record_hash: str
    ) -> bool: ...


class ExecutionService:
    def __init__(
        self,
        database_url: str,
        codec: ExecutionTokenCodec,
        receipt_gate: ReceiptGate | None = None,
        risk_provider: RiskProvider | None = None,
        security_event_pool: Any | None = None,
        security_event_pool_max_size: int = 2,
        security_event_pool_timeout_seconds: float = 0.25,
        default_token_ttl_seconds: int = 300,
        metrics: Metrics | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.pool = ConnectionPool(database_url, min_size=1, max_size=10, open=True)
        self.security_event_pool = security_event_pool or ConnectionPool(
            database_url,
            min_size=0,
            max_size=security_event_pool_max_size,
            timeout=security_event_pool_timeout_seconds,
            open=True,
        )
        self.codec = codec
        self.receipt_gate = receipt_gate
        self.risk_provider = risk_provider or RegistryFloorRiskProvider()
        self.security_event_counters: Counter[str] = Counter()
        self.metrics = metrics or Metrics()
        self.default_token_ttl_seconds = default_token_ttl_seconds
        self.rate_limiter = rate_limiter

    @staticmethod
    def _scope(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def issue(self, tenant_id: str, decision_id: str, executor_spiffe: str) -> str:
        now = datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            return self._issue_tx(connection, tenant_id, decision_id, executor_spiffe, now)

    def issue_for_decision(
        self,
        tenant_id: str,
        decision_id: str,
        requesting_agent_id: str,
        executor_spiffe_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue the capability a decision earned, at most once while one is live.

        B-16 default, pending ratification: only the decision's own agent principal may ask, and a
        repeat request returns the token already outstanding rather than minting a second one. The
        executor is chosen from the tool version's registered set (V-21) — a caller may name one of
        them, never propose a new one.
        """
        now = datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            # adr_records is append-only and mizan_app holds no UPDATE privilege on it, so the
            # serialization point is a transaction-scoped advisory lock on the decision, not a
            # row lock. Two concurrent requests for one decision cannot both mint a token.
            row = connection.execute(
                "SELECT document, pg_advisory_xact_lock(hashtextextended(%s, 0)) "
                "FROM mizan.adr_records WHERE tenant_id=%s AND decision_id=%s",
                (f"{tenant_id}:{decision_id}:execution-token", tenant_id, decision_id),
            ).fetchone()
            if not row:
                raise Problem(404, "decision_not_found", "Decision was not found")
            adr = row[0]
            if adr["agent"]["id"] != requesting_agent_id:
                raise Problem(
                    403,
                    "execution_token_requester_mismatch",
                    "Only the agent named by the decision may request its execution token",
                )
            outstanding = connection.execute(
                "SELECT claims FROM mizan.execution_tokens WHERE tenant_id=%s AND decision_id=%s "
                "AND consumed_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
                (tenant_id, decision_id),
            ).fetchone()
            if outstanding:
                # Deterministic Ed25519 over the stored claims: the same bytes, not a second grant.
                return {
                    "execution_token": self.codec.encode(outstanding[0]),
                    "expires_at": datetime.fromtimestamp(outstanding[0]["exp"], UTC)
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "reused": True,
                }
            if self.rate_limiter is not None:
                self.rate_limiter.require(tenant_id, "execution_token", adr["risk"]["level"])
            tool = connection.execute(
                "SELECT document FROM mizan.tools WHERE tenant_id=%s AND tool_id=%s",
                (tenant_id, adr["tool"]["id"]),
            ).fetchone()
            if not tool:
                raise Problem(404, "tool_not_found", "Decision names a tool that is not registered")
            executor = self._select_executor(tool[0], executor_spiffe_id)
            token = self._issue_tx(connection, tenant_id, decision_id, executor, now)
            claims = self.codec.decode(token)
            return {
                "execution_token": token,
                "expires_at": datetime.fromtimestamp(claims["exp"], UTC)
                .isoformat()
                .replace("+00:00", "Z"),
                "reused": False,
            }

    @staticmethod
    def _select_executor(tool: dict[str, Any], requested: str | None) -> str:
        registered = tool.get("execution", {}).get("executor_spiffe_ids", [])
        if requested is not None:
            if requested not in registered:
                raise Problem(
                    403,
                    "executor_not_authorized",
                    "Requested executor is not registered for this tool version",
                )
            return requested
        if len(registered) != 1:
            raise Problem(
                422,
                "executor_selection_required",
                f"This tool has {len(registered)} registered executors; name one of "
                f"{sorted(registered)}",
            )
        return registered[0]

    def _issue_tx(
        self,
        connection: Any,
        tenant_id: str,
        decision_id: str,
        executor_spiffe: str,
        now: datetime,
    ) -> str:
        row = connection.execute(
            """SELECT a.document,t.document,ag.lifecycle_state
                 FROM mizan.adr_records a
                 JOIN mizan.tools t ON t.tenant_id=a.tenant_id AND t.tool_id=a.tool_id
                 JOIN mizan.agents ag ON ag.tenant_id=a.tenant_id AND ag.agent_id=a.agent_id
                WHERE a.tenant_id=%s AND a.decision_id=%s""",
            (tenant_id, decision_id),
        ).fetchone()
        if not row:
            raise Problem(404, "decision_not_found", "Decision was not found")
        adr, tool, agent_state = row
        if adr["decision"] not in {"ALLOW", "REQUIRE_APPROVAL"}:
            raise Problem(403, "decision_not_executable", "Decision does not permit execution")
        approval_epoch = None
        if adr["decision"] == "REQUIRE_APPROVAL":
            approval = connection.execute(
                "SELECT document FROM mizan.approvals WHERE tenant_id=%s AND decision_id=%s",
                (tenant_id, decision_id),
            ).fetchone()
            if not approval or approval[0]["state"] not in {"APPROVED", "OVERRIDDEN"}:
                raise Problem(
                    403, "approval_incomplete", "Approval has not reached an executable state"
                )
            approval_epoch = approval[0]["current_epoch_id"]
        if agent_state not in {"ACTIVE", "MONITORED"}:
            raise Problem(403, "agent_not_active", "Agent is not active")
        executor = self._authorized_executor(tool, executor_spiffe)
        ttl = tool["execution"].get("token_ttl_seconds", self.default_token_ttl_seconds)
        policy_ttls: list[int] = []
        for policy_ref in adr["policies"]:
            policy = connection.execute(
                "SELECT document FROM mizan.policies WHERE tenant_id=%s AND policy_id=%s AND version=%s",
                (tenant_id, policy_ref["policy_id"], policy_ref["version"]),
            ).fetchone()
            if policy and policy[0].get("execution_token_ttl_seconds"):
                policy_ttls.append(policy[0]["execution_token_ttl_seconds"])
        ttl = self._clamp_token_ttl(ttl, policy_ttls)
        jti = uuid4().hex
        claims = {
            "token_version": "1.2",
            "jti": jti,
            "iss": self.codec.issuer,
            "aud": "mizan-execution-gateway",
            "tenant_id": tenant_id,
            "agent_id": adr["agent"]["id"],
            "principal_id": adr["principal"]["id"],
            "delegation_chain_hash": canonical_hash(adr["agent"]["delegation_chain"]),
            "authorized_executor": executor,
            "decision_id": decision_id,
            "tool_id": adr["tool"]["id"],
            "parameters_hash": adr["tool"]["parameters_hash"],
            "binding_profile": adr["tool"]["binding_profile"],
            "context_hash": adr["context_hash"],
            "approval_epoch_id": approval_epoch,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        }
        connection.execute(
            """INSERT INTO mizan.execution_tokens(
                 tenant_id,jti_hash,decision_id,agent_id,tool_id,authorized_executor,claims,expires_at
               ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                tenant_id,
                _jti_hash(jti),
                decision_id,
                claims["agent_id"],
                claims["tool_id"],
                executor,
                json.dumps(claims),
                datetime.fromtimestamp(claims["exp"], UTC),
            ),
        )
        append_decision_event_tx(
            connection,
            tenant_id,
            decision_id,
            "CAPABILITY_ISSUED",
            {"kind": "system", "id": "mizan-execution-service", "authenticated_workload": None},
            {"token_jti_hash": _jti_hash(jti), "approval_state": None},
            now,
        )
        return self.codec.encode(claims)

    @staticmethod
    def _authorized_executor(tool: dict[str, Any], executor_spiffe: str) -> str:
        if executor_spiffe not in tool.get("execution", {}).get("executor_spiffe_ids", []):
            raise Problem(
                403,
                "executor_not_authorized",
                "Issuing workload is not an authorized executor for this tool version",
            )
        return executor_spiffe

    @staticmethod
    def _clamp_token_ttl(tool_ttl: int, policy_ttls: list[int]) -> int:
        return min([tool_ttl, *policy_ttls])

    def redeem(
        self,
        token: str,
        decision_id: str,
        peer_spiffe: str,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        claims = self.codec.decode(token)
        tenant_id = claims["tenant_id"]
        if claims["decision_id"] != decision_id or claims["authorized_executor"] != peer_spiffe:
            raise Problem(403, "execution_binding_mismatch", "Decision or executor binding differs")
        now = datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            existing = None
            if idempotency_key:
                existing = connection.execute(
                    "SELECT document FROM mizan.execution_leases "
                    "WHERE tenant_id=%s AND decision_id=%s AND idempotency_key=%s",
                    (tenant_id, decision_id, idempotency_key),
                ).fetchone()
                if existing:
                    if existing[0]["authorized_executor"] != peer_spiffe:
                        raise Problem(
                            403,
                            "lease_executor_mismatch",
                            "Existing lease belongs to another executor",
                        )
                    existing = existing[0]
            row = connection.execute(
                """SELECT et.consumed_at,a.document,t.document,ag.lifecycle_state,ac.document
                     FROM mizan.execution_tokens et
                     JOIN mizan.adr_records a ON a.tenant_id=et.tenant_id AND a.decision_id=et.decision_id
                     JOIN mizan.authorization_contexts ac ON ac.tenant_id=et.tenant_id AND ac.decision_id=et.decision_id
                     JOIN mizan.tools t ON t.tenant_id=et.tenant_id AND t.tool_id=et.tool_id
                     JOIN mizan.agents ag ON ag.tenant_id=et.tenant_id AND ag.agent_id=et.agent_id
                     JOIN mizan.agent_tools at ON at.tenant_id=et.tenant_id AND at.agent_id=et.agent_id AND at.tool_id=et.tool_id
                    WHERE et.tenant_id=%s AND et.jti_hash=%s FOR UPDATE OF et""",
                (tenant_id, _jti_hash(claims["jti"])),
            ).fetchone()
            if row and row[0] is not None and existing is None:
                self._record_security_event(
                    tenant_id,
                    "mizan.security.execution_token_replay",
                    decision_id,
                    claims["jti"],
                    peer_spiffe,
                )
                raise Problem(
                    403,
                    "execution_token_consumed",
                    "Execution capability was already consumed and replayed",
                )
            if not row:
                raise Problem(
                    403, "execution_token_consumed", "Execution capability is absent or consumed"
                )
            adr, tool, agent_state, normalized_context = row[1], row[2], row[3], row[4]
            self._revalidate(
                connection,
                claims,
                adr,
                tool,
                agent_state,
                normalized_context,
                arguments,
            )
            if existing is not None:
                if existing["redeemed_jti"] != claims["jti"]:
                    raise Problem(
                        409,
                        "execution_idempotency_conflict",
                        "Idempotency key belongs to another capability",
                    )
                return existing
            if adr["action"]["type"] == "financial_write":
                self._require_receipts(connection, tenant_id, decision_id, adr)
            lease_id = "lse_" + uuid4().hex
            execution = tool["execution"]
            expires = now + timedelta(seconds=execution["lease_ttl_seconds"])
            lease = {
                "schema_version": "1.2",
                "lease_id": lease_id,
                "redeemed_jti": claims["jti"],
                "tenant_id": tenant_id,
                "agent_id": claims["agent_id"],
                "principal_id": claims["principal_id"],
                "authorized_executor": peer_spiffe,
                "decision_id": decision_id,
                "tool_id": claims["tool_id"],
                "state": "LEASED",
                "idempotency_key": idempotency_key,
                "granted_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": expires.isoformat().replace("+00:00", "Z"),
                "last_heartbeat_at": None,
                "heartbeat_interval_seconds": execution["heartbeat_interval_seconds"],
                "extensions_used": 0,
                "max_extensions": execution["max_lease_extensions"],
                "result_hash": None,
            }
            try:
                connection.execute(
                    """INSERT INTO mizan.execution_leases(
                         tenant_id,lease_id,redeemed_jti_hash,decision_id,agent_id,tool_id,principal_id,
                         authorized_executor,state,idempotency_key,extensions_used,max_extensions,
                         heartbeat_interval_seconds,document,expires_at
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        tenant_id,
                        lease_id,
                        _jti_hash(claims["jti"]),
                        decision_id,
                        claims["agent_id"],
                        claims["tool_id"],
                        claims["principal_id"],
                        peer_spiffe,
                        "LEASED",
                        idempotency_key,
                        0,
                        execution["max_lease_extensions"],
                        execution["heartbeat_interval_seconds"],
                        json.dumps(lease),
                        expires,
                    ),
                )
            except UniqueViolation as exc:
                raise Problem(
                    409, "execution_idempotency_conflict", "Idempotency key is already used"
                ) from exc
            updated = connection.execute(
                "UPDATE mizan.execution_tokens SET consumed_at=%s,lease_id=%s "
                "WHERE tenant_id=%s AND jti_hash=%s AND consumed_at IS NULL",
                (now, lease_id, tenant_id, _jti_hash(claims["jti"])),
            ).rowcount
            if updated != 1:
                raise Problem(
                    403, "execution_token_consumed", "Execution capability lost redemption race"
                )
            append_decision_event_tx(
                connection,
                tenant_id,
                decision_id,
                "LEASE_STARTED",
                {"kind": "service", "id": peer_spiffe, "authenticated_workload": peer_spiffe},
                {"lease_id": lease_id},
                now,
            )
            return lease

    def _record_security_event(
        self,
        tenant_id: str,
        event_type: str,
        decision_id: str,
        jti: str,
        peer_spiffe: str,
    ) -> None:
        """Write the SIEM row for a security event, and never let failing to change the answer.

        This runs *inside* the redemption transaction, on a separate bounded pool so it cannot
        take the redemption's connection. Until T-073 it caught `PoolTimeout` alone, so any other
        fault of the audit sink — a dropped connection, a serialization failure, a revoked grant —
        escaped, rolled the redemption back, and turned a detected replay of an execution
        capability into a 500. That inverts the control: the caller is told to retry, by the
        mechanism whose entire job was to refuse it. No failure of this sink may reach the
        decision, so every exception is absorbed here.

        A dropped event is **lost**, not deferred: there is no queue behind this. So the row we
        could not write is logged in full at ERROR, where the same pipeline that ships logs to the
        SIEM can recover it, and counted where an alert can see it. The payload carries ids and
        hashes only — the same fields the outbox row would have carried.
        """
        document = {
            "decision_id": decision_id,
            "token_jti_hash": _jti_hash(jti),
            "authenticated_workload": peer_spiffe,
        }
        try:
            with self.security_event_pool.connection() as connection, connection.transaction():
                self._scope(connection, tenant_id)
                connection.execute(
                    "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                    "VALUES (%s,'security',%s,%s,%s)",
                    (tenant_id, "security-" + uuid4().hex, event_type, json.dumps(document)),
                )
        except PoolTimeout:
            self._dropped_security_event(tenant_id, event_type, document, "pool_timeout", None)
        except Exception as exc:  # noqa: BLE001 - see the docstring: the sink may not decide
            self._dropped_security_event(
                tenant_id, event_type, document, type(exc).__name__, exc
            )

    def _dropped_security_event(
        self,
        tenant_id: str,
        event_type: str,
        document: dict[str, Any],
        cause: str,
        error: BaseException | None,
    ) -> None:
        metric = "security_event_pool_timeout" if cause == "pool_timeout" else "security_event_write_failed"
        self.security_event_counters[metric] += 1
        self.metrics.security_events_dropped.labels(tenant_id, event_type, cause).inc()
        LOGGER.error(
            "security event dropped and lost",
            extra={
                "tenant_id": tenant_id,
                "event_type": event_type,
                "cause": cause,
                "metric": metric,
                "dropped_event": json.dumps(document, sort_keys=True),
                **document,
            },
            exc_info=error,
        )

    def heartbeat(
        self, tenant_id: str, decision_id: str, lease_id: str, peer_spiffe: str
    ) -> dict[str, Any]:
        return self._transition_lease(
            tenant_id, decision_id, lease_id, peer_spiffe, "heartbeat", None
        )

    def complete(
        self,
        tenant_id: str,
        decision_id: str,
        lease_id: str,
        peer_spiffe: str,
        result_hash: str | None,
        failure_code: str | None,
    ) -> dict[str, Any]:
        return self._transition_lease(
            tenant_id,
            decision_id,
            lease_id,
            peer_spiffe,
            "complete",
            {"result_hash": result_hash, "failure_code": failure_code},
        )

    def _transition_lease(
        self,
        tenant_id: str,
        decision_id: str,
        lease_id: str,
        peer_spiffe: str,
        operation: str,
        outcome: dict[str, Any] | None,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        terminal_error: Problem | None = None
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document FROM mizan.execution_leases WHERE tenant_id=%s AND lease_id=%s "
                "AND decision_id=%s FOR UPDATE",
                (tenant_id, lease_id, decision_id),
            ).fetchone()
            if not row:
                raise Problem(404, "lease_not_found", "Execution lease was not found")
            lease = row[0]
            if lease["authorized_executor"] != peer_spiffe:
                raise Problem(403, "lease_executor_mismatch", "Workload does not own this lease")
            if lease["state"] in {"EXECUTED", "FAILED", "LEASE_EXPIRED"}:
                raise Problem(409, "lease_terminal", "Execution lease is terminal")
            if now >= datetime.fromisoformat(lease["expires_at"].replace("Z", "+00:00")):
                lease["state"] = "LEASE_EXPIRED"
                self._save_lease(connection, tenant_id, lease)
                append_decision_event_tx(
                    connection,
                    tenant_id,
                    decision_id,
                    "LEASE_EXPIRED",
                    {
                        "kind": "system",
                        "id": "mizan-execution-service",
                        "authenticated_workload": None,
                    },
                    {"lease_id": lease_id},
                    now,
                )
                terminal_error = Problem(409, "lease_expired", "Execution lease expired")
            elif operation == "heartbeat":
                if lease["extensions_used"] >= lease["max_extensions"]:
                    raise Problem(
                        409, "lease_extension_exhausted", "Lease extension budget is exhausted"
                    )
                tool = connection.execute(
                    "SELECT document FROM mizan.tools WHERE tenant_id=%s AND tool_id=%s",
                    (tenant_id, lease["tool_id"]),
                ).fetchone()[0]
                lease["extensions_used"] += 1
                lease["last_heartbeat_at"] = now.isoformat().replace("+00:00", "Z")
                lease["expires_at"] = (
                    (now + timedelta(seconds=tool["execution"]["lease_ttl_seconds"]))
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                lease["state"] = "EXECUTING"
                event_type, payload = "LEASE_EXTENDED", {"lease_id": lease_id}
            elif operation == "complete":
                assert outcome is not None
                lease["state"] = "FAILED" if outcome["failure_code"] else "EXECUTED"
                lease["result_hash"] = outcome["result_hash"]
                event_type = (
                    "EXECUTION_FAILED" if outcome["failure_code"] else "EXECUTION_COMPLETED"
                )
                payload = {"lease_id": lease_id, **outcome}
            if terminal_error is None:
                self._save_lease(connection, tenant_id, lease)
                append_decision_event_tx(
                    connection,
                    tenant_id,
                    decision_id,
                    event_type,
                    {
                        "kind": "service",
                        "id": peer_spiffe,
                        "authenticated_workload": peer_spiffe,
                    },
                    payload,
                    now,
                )
        if terminal_error is not None:
            raise terminal_error
        return lease

    _save_lease = staticmethod(save_lease_tx)

    def sweep_expired_leases(
        self, tenant_id: str, limit: int = 100, now: datetime | None = None
    ) -> list[str]:
        """Expire leases whose holder never came back. Returns the lease ids expired.

        `LEASE_EXPIRED` was reachable from exactly one place -- `_transition_lease`, which first
        requires `lease["authorized_executor"] == peer_spiffe`. So the only party who could
        expire a lease was the party holding it, and an executor that crashed simply never called
        again: the lease stayed `LEASED` or `EXECUTING` for ever, the decision never reached a
        terminal state, and SPEC 5.6's *"no heartbeat within lease_ttl -> LEASE_EXPIRED"* was a
        sentence no code path could execute. The cause was structural rather than a missed
        branch -- this process had no background task of any kind.

        Each lease is expired in **its own transaction**, so one that cannot be written does not
        roll back the others, and the row is re-read `FOR UPDATE` inside that transaction because
        the holder may have completed or extended it between the scan and the write -- in which
        case the state check drops it and the holder's own outcome stands.

        The write is outbox-transactional by construction: `append_decision_event_tx` inserts the
        DecisionEvent, its chain links and the `mizan.outbox` row in the same transaction as the
        state change, so an expiry that is recorded is one that will be published, and one that
        fails leaves nothing behind to reconcile.
        """
        now = now or datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            candidates = [
                (row[0], row[1])
                for row in connection.execute(
                    "SELECT lease_id,decision_id FROM mizan.execution_leases "
                    "WHERE tenant_id=%s AND state IN ('LEASED','EXECUTING') AND expires_at<=%s "
                    "ORDER BY expires_at LIMIT %s",
                    (tenant_id, now, limit),
                ).fetchall()
            ]

        expired: list[str] = []
        for lease_id, decision_id in candidates:
            with self.pool.connection() as connection, connection.transaction():
                self._scope(connection, tenant_id)
                row = connection.execute(
                    "SELECT document FROM mizan.execution_leases "
                    "WHERE tenant_id=%s AND lease_id=%s AND state IN ('LEASED','EXECUTING') "
                    "AND expires_at<=%s FOR UPDATE",
                    (tenant_id, lease_id, now),
                ).fetchone()
                if row is None:
                    # Completed, failed or extended between the scan and here. The holder wins.
                    continue
                lease = row[0]
                lease["state"] = "LEASE_EXPIRED"
                self._save_lease(connection, tenant_id, lease)
                append_decision_event_tx(
                    connection,
                    tenant_id,
                    decision_id,
                    "LEASE_EXPIRED",
                    {
                        "kind": "system",
                        "id": "mizan-lease-sweeper",
                        "authenticated_workload": None,
                    },
                    # Named so an auditor can tell an expiry nobody was present for from one a
                    # holder discovered by calling in. Both are LEASE_EXPIRED; only one of them
                    # means the executor vanished.
                    {"lease_id": lease_id, "detected_by": "sweep"},
                    now,
                )
                expired.append(lease_id)
        return expired

    def _revalidate(
        self,
        connection: Any,
        claims: dict[str, Any],
        adr: dict[str, Any],
        tool: dict[str, Any],
        agent_state: str,
        normalized_context: dict[str, Any],
        arguments: dict[str, Any],
    ) -> None:
        expected = {
            "tenant_id": adr["tenant_id"],
            "agent_id": adr["agent"]["id"],
            "principal_id": adr["principal"]["id"],
            "tool_id": adr["tool"]["id"],
            "parameters_hash": adr["tool"]["parameters_hash"],
            "context_hash": adr["context_hash"],
            "binding_profile": adr["tool"]["binding_profile"],
            "delegation_chain_hash": canonical_hash(adr["agent"]["delegation_chain"]),
        }
        if any(claims[key] != value for key, value in expected.items()):
            raise Problem(
                403, "execution_context_drift", "Capability no longer matches decision context"
            )
        current_profile = tool["binding_profile"]
        if claims["binding_profile"] != {
            "profile_id": current_profile["profile_id"],
            "profile_version": current_profile["profile_version"],
        }:
            raise Problem(403, "binding_profile_mismatch", "Tool binding profile identity changed")
        if claims["authorized_executor"] not in tool["execution"]["executor_spiffe_ids"]:
            raise Problem(
                403, "executor_mapping_changed", "Executor is no longer authorized by tool version"
            )
        if agent_state not in {"ACTIVE", "MONITORED"}:
            raise Problem(403, "agent_not_active", "Agent is no longer active")
        profile = connection.execute(
            "SELECT bound_pointers,volatile_pointers FROM mizan.binding_profiles "
            "WHERE tenant_id=%s AND profile_id=%s AND profile_version=%s",
            (
                claims["tenant_id"],
                claims["binding_profile"]["profile_id"],
                claims["binding_profile"]["profile_version"],
            ),
        ).fetchone()
        if not profile:
            raise Problem(403, "binding_profile_missing", "Pinned binding profile is unavailable")
        validate_binding_arguments(arguments, profile[0], profile[1])
        if binding_hash(arguments, profile[0]) != claims["parameters_hash"]:
            raise Problem(
                403, "execution_arguments_drift", "Execution arguments differ from authorization"
            )
        current_context = json.loads(json.dumps(normalized_context))
        current_context["tool"]["arguments"] = arguments
        try:
            evaluation_context = EvaluationContext.model_validate(current_context)
        except ValueError as exc:
            raise Problem(
                403, "execution_context_invalid", "Stored context cannot be revalidated"
            ) from exc
        agent = connection.execute(
            "SELECT version,parent_agent_id,document FROM mizan.agents "
            "WHERE tenant_id=%s AND agent_id=%s",
            (claims["tenant_id"], claims["agent_id"]),
        ).fetchone()
        if not agent or agent[0] != evaluation_context.agent.version:
            raise Problem(403, "agent_version_changed", "Agent version changed after authorization")
        chain = adr["agent"]["delegation_chain"]
        previous_document = None
        root_document = None
        for index, agent_id in enumerate(chain):
            current = connection.execute(
                "SELECT parent_agent_id,lifecycle_state,document,"
                "EXISTS(SELECT 1 FROM mizan.agent_tools at WHERE at.tenant_id=a.tenant_id "
                "AND at.agent_id=a.agent_id AND at.tool_id=%s) "
                "FROM mizan.agents a WHERE tenant_id=%s AND agent_id=%s",
                (claims["tool_id"], claims["tenant_id"], agent_id),
            ).fetchone()
            expected_parent = None if index == 0 else chain[index - 1]
            if (
                not current
                or current[0] != expected_parent
                or current[1] not in {"ACTIVE", "MONITORED"}
                or not current[3]
            ):
                raise Problem(
                    403,
                    "delegation_authority_changed",
                    "Delegation chain or tool authority changed after authorization",
                )
            if index:
                self._require_delegation_edge(previous_document, agent_id)
            previous_document = current[2]
            if index == 0:
                root_document = current[2]
        if len(chain) > root_document.get("delegation", {}).get("max_delegation_depth", 0) + 1:
            raise Problem(403, "delegation_authority_changed", "Delegation depth changed")
        evaluation_context.resource.resource_owner = tool["resource_owner"]
        classifications = [
            "public",
            "internal",
            "confidential",
            "pii",
            "financial",
            "secret",
        ]
        if classifications.index(tool["data_classification"]) > classifications.index(
            evaluation_context.resource.data_classification
        ):
            evaluation_context.resource.data_classification = tool["data_classification"]
        refreshed = evaluation_context.model_dump(mode="json", exclude={"tenant_id"})
        refreshed["tool"].pop("arguments")
        if canonical_hash(refreshed) != claims["context_hash"]:
            raise Problem(403, "execution_context_drift", "Authoritative context changed")
        try:
            risk = self.risk_provider.evaluate(evaluation_context, tool["risk_tier"])
        except Exception as exc:
            raise Problem(
                503, "risk_engine_unavailable", "Execution risk revalidation failed"
            ) from exc
        if RISK_ORDER[risk["level"]] < RISK_ORDER[tool["risk_tier"]]:
            risk["level"] = tool["risk_tier"]
        if RISK_ORDER[risk["level"]] > RISK_ORDER[adr["risk"]["level"]]:
            raise Problem(
                403, "execution_risk_increased", "Execution risk increased after authorization"
            )
        if claims.get("approval_epoch_id") is not None:
            approval = connection.execute(
                "SELECT document FROM mizan.approvals WHERE tenant_id=%s AND decision_id=%s",
                (claims["tenant_id"], claims["decision_id"]),
            ).fetchone()
            if (
                not approval
                or approval[0]["state"] not in {"APPROVED", "OVERRIDDEN"}
                or approval[0]["current_epoch_id"] != claims["approval_epoch_id"]
            ):
                raise Problem(
                    403,
                    "approval_epoch_changed",
                    "Approval epoch is no longer executable",
                )

    @staticmethod
    def _require_delegation_edge(
        previous_document: dict[str, Any] | None, agent_id: str
    ) -> None:
        delegation = (
            previous_document.get("delegation")
            if isinstance(previous_document, dict)
            else None
        )
        if not isinstance(delegation, dict) or agent_id not in delegation.get(
            "allowed_agent_ids", []
        ):
            raise Problem(
                403,
                "delegation_authority_changed",
                "Delegation edge is no longer authorized",
            )

    def _require_receipts(
        self, connection: Any, tenant_id: str, decision_id: str, adr: dict[str, Any]
    ) -> None:
        if self.receipt_gate is None:
            raise Problem(
                503,
                "receipt_verifier_unavailable",
                "Financial execution requires the external evidence verifier",
            )
        adr_receipt = connection.execute(
            "SELECT 1 FROM mizan.evidence_receipts WHERE tenant_id=%s AND stream_id=%s "
            "AND sequence_number=%s AND record_hash=%s",
            (tenant_id, adr["stream_id"], adr["sequence_number"], adr["record_hash"]),
        ).fetchone()
        if not adr_receipt:
            raise Problem(
                403, "immutable_receipt_missing", "Financial decision is not durably published"
            )
        if not self.receipt_gate.verify_record_receipt(
            tenant_id, adr["stream_id"], adr["sequence_number"], adr["record_hash"]
        ):
            raise Problem(403, "immutable_receipt_invalid", "Financial decision receipt is invalid")
        if adr["approval"]["required"]:
            approval_receipt = connection.execute(
                """SELECT de.stream_id,de.sequence_number,de.record_hash FROM mizan.decision_events de JOIN mizan.evidence_receipts er
                     ON er.tenant_id=de.tenant_id AND er.stream_id=de.stream_id
                    AND er.sequence_number=de.sequence_number AND er.record_hash=de.record_hash
                    WHERE de.tenant_id=%s AND de.decision_id=%s AND de.event_type='APPROVAL_RESOLVED'
                    ORDER BY de.decision_sequence DESC LIMIT 1""",
                (tenant_id, decision_id),
            ).fetchone()
            if not approval_receipt:
                raise Problem(
                    403, "approval_receipt_missing", "Approval evidence is not durably published"
                )
            if not self.receipt_gate.verify_record_receipt(
                tenant_id, approval_receipt[0], approval_receipt[1], approval_receipt[2]
            ):
                raise Problem(403, "approval_receipt_invalid", "Approval receipt is invalid")
