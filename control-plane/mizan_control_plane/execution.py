from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from psycopg.errors import UniqueViolation
from psycopg_pool import ConnectionPool

from .canonical import canonical_hash
from .evidence import append_decision_event_tx
from .problems import Problem


def _jti_hash(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


class ExecutionTokenCodec:
    def __init__(
        self,
        issuer: str,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey | None = None,
        clock_skew_seconds: int = 30,
    ) -> None:
        self.issuer = issuer
        self.private_key = private_key
        self.public_key = public_key or private_key.public_key()
        self.clock_skew_seconds = clock_skew_seconds

    def encode(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self.private_key, algorithm="EdDSA", headers={"typ": "JWT"})

    def decode(self, token: str) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                issuer=self.issuer,
                audience="mizan-execution-gateway",
                leeway=self.clock_skew_seconds,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "jti"]},
            )
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
    ) -> None:
        self.pool = ConnectionPool(database_url, min_size=1, max_size=10, open=True)
        self.codec = codec
        self.receipt_gate = receipt_gate

    @staticmethod
    def _scope(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def issue(self, tenant_id: str, decision_id: str) -> str:
        now = datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                """SELECT a.document,t.document,ag.lifecycle_state
                     FROM mizan.adr_records a
                     JOIN mizan.tools t ON t.tenant_id=a.tenant_id AND t.tool_id=a.tool_id
                     JOIN mizan.agents ag ON ag.tenant_id=a.tenant_id AND ag.agent_id=a.agent_id
                    WHERE a.tenant_id=%s AND a.decision_id=%s FOR UPDATE OF a""",
                (tenant_id, decision_id),
            ).fetchone()
            if not row:
                raise Problem(404, "decision_not_found", "Decision was not found")
            adr, tool, agent_state = row
            if adr["decision"] not in {"ALLOW", "CONSTRAIN", "REDACT", "REQUIRE_APPROVAL"}:
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
            executor = tool["execution"]["executor_spiffe_ids"][0]
            ttl = tool["execution"]["token_ttl_seconds"]
            for policy_ref in adr["policies"]:
                policy = connection.execute(
                    "SELECT document FROM mizan.policies WHERE tenant_id=%s AND policy_id=%s AND version=%s",
                    (tenant_id, policy_ref["policy_id"], policy_ref["version"]),
                ).fetchone()
                if policy and policy[0].get("execution_token_ttl_seconds"):
                    ttl = min(ttl, policy[0]["execution_token_ttl_seconds"])
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
                "constraints_hash": canonical_hash(adr.get("constraints"))
                if adr.get("constraints")
                else None,
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

    def redeem(
        self,
        token: str,
        decision_id: str,
        peer_spiffe: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        claims = self.codec.decode(token)
        tenant_id = claims["tenant_id"]
        if claims["decision_id"] != decision_id or claims["authorized_executor"] != peer_spiffe:
            raise Problem(403, "execution_binding_mismatch", "Decision or executor binding differs")
        now = datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
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
                    return existing[0]
            row = connection.execute(
                """SELECT et.consumed_at,a.document,t.document,ag.lifecycle_state
                     FROM mizan.execution_tokens et
                     JOIN mizan.adr_records a ON a.tenant_id=et.tenant_id AND a.decision_id=et.decision_id
                     JOIN mizan.tools t ON t.tenant_id=et.tenant_id AND t.tool_id=et.tool_id
                     JOIN mizan.agents ag ON ag.tenant_id=et.tenant_id AND ag.agent_id=et.agent_id
                    WHERE et.tenant_id=%s AND et.jti_hash=%s FOR UPDATE OF et""",
                (tenant_id, _jti_hash(claims["jti"])),
            ).fetchone()
            if not row or row[0] is not None:
                raise Problem(
                    403, "execution_token_consumed", "Execution capability is absent or consumed"
                )
            adr, tool, agent_state = row[1], row[2], row[3]
            self._revalidate(connection, claims, adr, tool, agent_state)
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
                raise Problem(409, "lease_expired", "Execution lease expired")
            if operation == "heartbeat":
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
            else:
                assert outcome is not None
                lease["state"] = "FAILED" if outcome["failure_code"] else "EXECUTED"
                lease["result_hash"] = outcome["result_hash"]
                event_type = (
                    "EXECUTION_FAILED" if outcome["failure_code"] else "EXECUTION_COMPLETED"
                )
                payload = {"lease_id": lease_id, **outcome}
            self._save_lease(connection, tenant_id, lease)
            append_decision_event_tx(
                connection,
                tenant_id,
                decision_id,
                event_type,
                {"kind": "service", "id": peer_spiffe, "authenticated_workload": peer_spiffe},
                payload,
                now,
            )
            return lease

    @staticmethod
    def _save_lease(connection: Any, tenant_id: str, lease: dict[str, Any]) -> None:
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

    @staticmethod
    def _revalidate(
        connection: Any,
        claims: dict[str, Any],
        adr: dict[str, Any],
        tool: dict[str, Any],
        agent_state: str,
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
