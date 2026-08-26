from __future__ import annotations

import base64
import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg_pool import ConnectionPool

from .attestation import Rfc3161AnchorProvider
from .canonical import canonical_hash
from .keys import KeyRole, SigningKey, development_key_provider
from .problems import Problem


class DeliverySink(Protocol):
    def publish(self, event_type: str, key: str, payload: dict[str, Any]) -> None: ...


class NullDeliverySink:
    def publish(self, event_type: str, key: str, payload: dict[str, Any]) -> None:
        return None


class AnchorProvider(Protocol):
    def attest(self, anchor_payload: dict[str, Any]) -> dict[str, Any] | list[dict[str, Any]]: ...


class DevelopmentUnattestedAnchorProvider:
    """Explicit no-trust provider for development; never an external attestation."""

    def attest(self, anchor_payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "none_development",
            "status": "unattested",
            "authority": "development",
            "obtained_at": None,
            "evidence": None,
        }


def anchor_provider_from_config(name: str | None = None) -> AnchorProvider:
    selected = name or os.environ.get("MIZAN_ANCHOR_PROVIDER", "development-unattested")
    if selected == "development-unattested":
        return DevelopmentUnattestedAnchorProvider()
    if selected == "rfc3161":
        endpoints = [item for item in os.environ.get("MIZAN_ANCHOR_TSA_ENDPOINTS", "").split(",") if item]
        trust_anchors = [
            Path(item)
            for item in os.environ.get("MIZAN_ANCHOR_TSA_TRUST_ANCHORS", "").split(",")
            if item
        ]
        return Rfc3161AnchorProvider(endpoints, trust_anchors)
    raise RuntimeError(f"anchor provider {selected!r} is not implemented")


class LocalImmutableObjectStore:
    """Development WORM analogue: create-only objects addressed by content version."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put_once(self, key: str, payload: bytes) -> str:
        target = (self.root / key).resolve()
        if self.root not in target.parents:
            raise ValueError("object key escapes evidence root")
        target.parent.mkdir(parents=True, exist_ok=True)
        version = canonical_hash({"key": key, "payload_sha256": canonical_hash_bytes(payload)})
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
        except FileExistsError:
            if target.read_bytes() != payload:
                raise RuntimeError("immutable object collision") from None
            return version
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        return version

    def get(self, key: str) -> bytes:
        target = (self.root / key).resolve()
        if self.root not in target.parents:
            raise ValueError("object key escapes evidence root")
        return target.read_bytes()


def canonical_hash_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class Ed25519EvidenceSigner:
    signing_key: SigningKey

    @classmethod
    def development(cls, role: KeyRole = "evidence-receipt") -> Ed25519EvidenceSigner:
        return cls(development_key_provider().active_key(role))

    @property
    def key_id(self) -> str:
        return self.signing_key.key_id

    def sign(self, payload: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(self.signing_key.sign(rfc8785.dumps(payload))).decode()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.signing_key.public_key()


def verify_signature(payload: dict[str, Any], signature: str, key: Ed25519PublicKey) -> None:
    key.verify(base64.urlsafe_b64decode(signature), rfc8785.dumps(payload))


def append_decision_event_tx(
    connection: Any,
    tenant_id: str,
    decision_id: str,
    event_type: str,
    actor: dict[str, Any],
    payload: dict[str, Any],
    occurred_at: datetime,
) -> dict[str, Any]:
    adr = connection.execute(
        "SELECT stream_id FROM mizan.adr_records WHERE tenant_id=%s AND decision_id=%s",
        (tenant_id, decision_id),
    ).fetchone()
    if not adr:
        raise Problem(404, "decision_not_found", "Decision does not exist")
    stream_id = adr[0]
    idempotency_key = canonical_hash(
        {"decision_id": decision_id, "event_type": event_type, "actor": actor, "payload": payload}
    )
    existing = connection.execute(
        "SELECT document FROM mizan.decision_events "
        "WHERE tenant_id=%s AND decision_id=%s AND idempotency_key=%s",
        (tenant_id, decision_id, idempotency_key),
    ).fetchone()
    if existing:
        return existing[0]
    connection.execute(
        "INSERT INTO mizan.decision_event_heads(tenant_id,decision_id) VALUES (%s,%s) "
        "ON CONFLICT DO NOTHING",
        (tenant_id, decision_id),
    )
    event_head = connection.execute(
        "SELECT next_sequence,last_hash FROM mizan.decision_event_heads "
        "WHERE tenant_id=%s AND decision_id=%s FOR UPDATE",
        (tenant_id, decision_id),
    ).fetchone()
    evidence_head = connection.execute(
        "SELECT next_sequence,last_hash FROM mizan.evidence_chain_heads "
        "WHERE tenant_id=%s AND stream_id=%s FOR UPDATE",
        (tenant_id, stream_id),
    ).fetchone()
    existing = connection.execute(
        "SELECT document FROM mizan.decision_events "
        "WHERE tenant_id=%s AND decision_id=%s AND idempotency_key=%s",
        (tenant_id, decision_id, idempotency_key),
    ).fetchone()
    if existing:
        return existing[0]
    event_id = "dev_" + uuid4().hex
    document = {
        "schema_version": "1.2",
        "event_id": event_id,
        "tenant_id": tenant_id,
        "decision_id": decision_id,
        "decision_sequence": event_head[0],
        "previous_event_hash": None if event_head[0] == 1 else event_head[1],
        "event_type": event_type,
        "actor": actor,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "payload": payload,
        "stream_id": stream_id,
        "sequence_number": evidence_head[0],
        "prev_hash": evidence_head[1],
        "record_hash": "0" * 64,
        "hash_alg": "SHA-256",
        "canonicalization": "RFC8785",
        "immutable_receipt_ref": None,
    }
    document["record_hash"] = canonical_hash(
        {key: value for key, value in document.items() if key != "record_hash"}
    )
    event_sequence = connection.execute(
        "SELECT mizan.reserve_decision_event_sequence(%s,%s,%s,%s)",
        (tenant_id, decision_id, event_head[1], document["record_hash"]),
    ).fetchone()[0]
    evidence_sequence = connection.execute(
        "SELECT mizan.reserve_evidence_sequence(%s,%s,%s,%s)",
        (tenant_id, stream_id, evidence_head[1], document["record_hash"]),
    ).fetchone()[0]
    if (event_sequence, evidence_sequence) != (
        document["decision_sequence"],
        document["sequence_number"],
    ):
        raise RuntimeError("DecisionEvent sequence allocation mismatch")
    connection.execute(
        """INSERT INTO mizan.decision_events(
             tenant_id,event_id,decision_id,decision_sequence,event_type,idempotency_key,previous_event_hash,
             event_hash,stream_id,sequence_number,prev_hash,record_hash,document,occurred_at
           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            tenant_id,
            event_id,
            decision_id,
            event_sequence,
            event_type,
            idempotency_key,
            event_head[1],
            document["record_hash"],
            stream_id,
            evidence_sequence,
            evidence_head[1],
            document["record_hash"],
            json.dumps(document),
            occurred_at,
        ),
    )
    connection.execute(
        "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
        "VALUES (%s,'decision_event',%s,%s,%s)",
        (tenant_id, event_id, f"mizan.decision.{event_type.lower()}", json.dumps(document)),
    )
    return document


class EvidenceRepository:
    def __init__(self, database_url: str) -> None:
        self.pool = ConnectionPool(database_url, min_size=1, max_size=10, open=True)

    @staticmethod
    def _scope(connection: Any, tenant_id: str) -> None:
        connection.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))

    def unpublished(
        self, tenant_id: str, limit: int = 100, evidence_only: bool = False
    ) -> list[dict[str, Any]]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            clause = (
                " AND aggregate_type IN ('decision','decision_event','audit')"
                if evidence_only
                else ""
            )
            rows = connection.execute(
                "SELECT outbox_id,event_type,payload,created_at FROM mizan.outbox "
                "WHERE tenant_id=%s AND published_at IS NULL"
                + clause
                + " ORDER BY outbox_id LIMIT %s FOR UPDATE SKIP LOCKED",
                (tenant_id, limit),
            ).fetchall()
            return [
                {"outbox_id": row[0], "event_type": row[1], "payload": row[2], "created_at": row[3]}
                for row in rows
            ]

    def append_audit(
        self,
        tenant_id: str,
        event_type: str,
        actor: dict[str, Any],
        subject: dict[str, Any],
        redacted: Any,
        trace_id: str | None = None,
        shard: int = 0,
    ) -> dict[str, Any]:
        attestation = getattr(redacted, "redaction", None)
        required = {
            "policy_id",
            "policy_version",
            "policy_hash",
            "redactor_build",
            "dlp",
            "manifest",
        }
        if not isinstance(attestation, dict) or not required <= attestation.keys():
            raise Problem(503, "redaction_attestation_missing", "Audit write lacks DLP attestation")
        dlp = attestation.get("dlp", {})
        if (
            dlp.get("status") == "scan_failed"
            or not dlp.get("scanner_version")
            or not dlp.get("coverage_profile")
        ):
            raise Problem(
                503, "redaction_attestation_invalid", "Audit DLP attestation failed closed"
            )
        if not getattr(redacted, "stored_payload_hash", None) or not getattr(
            redacted, "source_commitment", None
        ):
            raise Problem(503, "redaction_commitment_missing", "Audit commitments are incomplete")
        if canonical_hash(redacted.payload) != redacted.stored_payload_hash:
            raise Problem(
                503,
                "redaction_payload_hash_mismatch",
                "Stored audit payload does not match its redaction commitment",
            )
        manifest = attestation.get("manifest", [])
        if dlp.get("findings_count") != len(manifest):
            raise Problem(
                503,
                "redaction_manifest_incomplete",
                "DLP finding count does not match the redaction manifest",
            )
        for entry in manifest:
            if not self._manifest_transform_is_present(redacted.payload, entry):
                raise Problem(
                    503,
                    "redaction_transform_missing",
                    "Stored audit payload does not reflect its redaction manifest",
                )
        now = datetime.now(UTC)
        stream_id = f"{tenant_id}:audit:{shard}"
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING",
                (tenant_id, stream_id),
            )
            head = connection.execute(
                "SELECT next_sequence,last_hash FROM mizan.evidence_chain_heads "
                "WHERE tenant_id=%s AND stream_id=%s FOR UPDATE",
                (tenant_id, stream_id),
            ).fetchone()
            audit_id = "aud_" + uuid4().hex
            document = {
                "schema_version": "1.1",
                "audit_id": audit_id,
                "tenant_id": tenant_id,
                "stream_id": stream_id,
                "sequence_number": head[0],
                "event_type": event_type,
                "trace_id": trace_id,
                "actor": actor,
                "subject": subject,
                "payload": redacted.payload,
                "stored_payload_hash": redacted.stored_payload_hash,
                "source_commitment": redacted.source_commitment,
                "redaction": redacted.redaction,
                "timestamp": now.isoformat().replace("+00:00", "Z"),
                "prev_hash": head[1],
                "record_hash": "0" * 64,
                "hash_alg": "SHA-256",
                "canonicalization": "RFC8785",
                "anchor_ref": None,
                "retention_class": "regulatory_7y",
                "exported_to": [],
            }
            document["record_hash"] = canonical_hash(
                {key: value for key, value in document.items() if key != "record_hash"}
            )
            sequence = connection.execute(
                "SELECT mizan.reserve_evidence_sequence(%s,%s,%s,%s)",
                (tenant_id, stream_id, head[1], document["record_hash"]),
            ).fetchone()[0]
            if sequence != head[0]:
                raise RuntimeError("Audit sequence allocation mismatch")
            connection.execute(
                """INSERT INTO mizan.audit_trails(
                     tenant_id,audit_id,stream_id,sequence_number,prev_hash,record_hash,document,occurred_at
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    tenant_id,
                    audit_id,
                    stream_id,
                    sequence,
                    head[1],
                    document["record_hash"],
                    json.dumps(document),
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'audit',%s,%s,%s)",
                (tenant_id, audit_id, event_type, json.dumps(document)),
            )
            return document

    @staticmethod
    def _manifest_transform_is_present(payload: Any, entry: dict[str, Any]) -> bool:
        if entry.get("transformation") == "drop":
            # Array deletion shifts later indexes, so absence at the original pointer is not
            # independently observable. The keyed field commitment remains the drop evidence.
            return True
        parts = entry.get("pointer", "").removeprefix("/").split("/")
        current = payload
        try:
            for encoded in parts:
                key = encoded.replace("~1", "/").replace("~0", "~")
                current = current[int(key)] if isinstance(current, list) else current[key]
        except (KeyError, IndexError, TypeError, ValueError):
            return False
        expected = {
            "mask": "***REDACTED***",
            "tokenize": "tok_" + entry.get("commitment", "")[:24],
            "hash": "hmac_" + entry.get("commitment", ""),
            "generalize": "[generalized]",
        }
        operation = entry.get("transformation")
        return current == expected.get(operation)

    def record_redaction_failure(self, tenant_id: str, details: dict[str, str]) -> None:
        safe_details = {
            key: details[key]
            for key in ("redactor_build", "scanner_version", "coverage_profile")
            if details.get(key)
        }
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                "INSERT INTO mizan.outbox(tenant_id,aggregate_type,aggregate_id,event_type,payload) "
                "VALUES (%s,'security',%s,'mizan.security.redaction_failed',%s)",
                (tenant_id, "redaction-failure-" + uuid4().hex, json.dumps(safe_details)),
            )

    def record_publication(
        self, tenant_id: str, outbox_id: int, receipt: dict[str, Any], signature: str
    ) -> None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                """INSERT INTO mizan.evidence_receipts(
                     tenant_id,receipt_id,stream_id,sequence_number,record_hash,object_version,
                     object_key,key_id,signature,signed_payload
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    tenant_id,
                    receipt["receipt_id"],
                    receipt["stream_id"],
                    receipt["sequence_number"],
                    receipt["record_hash"],
                    receipt["object_version"],
                    receipt["object_key"],
                    receipt["key_id"],
                    signature,
                    json.dumps(receipt),
                ),
            )
            updated = connection.execute(
                "UPDATE mizan.outbox SET published_at=clock_timestamp(),attempts=attempts+1 "
                "WHERE tenant_id=%s AND outbox_id=%s AND published_at IS NULL",
                (tenant_id, outbox_id),
            ).rowcount
            if updated not in {0, 1}:
                raise RuntimeError("outbox publication cardinality violation")

    def stream_records(
        self, tenant_id: str, stream_id: str, start: int | None, end: int | None
    ) -> list[dict[str, Any]]:
        predicates, params = ["tenant_id=%s", "stream_id=%s"], [tenant_id, stream_id]
        if start is not None:
            predicates.append("sequence_number >= %s")
            params.append(start)
        if end is not None:
            predicates.append("sequence_number <= %s")
            params.append(end)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            where = " AND ".join(predicates)
            query = (
                "SELECT document,sequence_number FROM mizan.adr_records WHERE "
                + where
                + " UNION ALL SELECT document,(document->>'sequence_number')::bigint "
                "FROM mizan.decision_events WHERE "
                + where
                + " UNION ALL SELECT document,sequence_number FROM mizan.audit_trails WHERE "
                + where
                + " ORDER BY sequence_number"
            )
            return [
                row[0] for row in connection.execute(query, [*params, *params, *params]).fetchall()
            ]

    def append_decision_event(
        self,
        tenant_id: str,
        decision_id: str,
        event_type: str,
        actor: dict[str, Any],
        payload: dict[str, Any],
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        occurred_at = occurred_at or datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            return append_decision_event_tx(
                connection,
                tenant_id,
                decision_id,
                event_type,
                actor,
                payload,
                occurred_at,
            )

    def has_receipt(self, tenant_id: str, stream_id: str, sequence: int, record_hash: str) -> bool:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            return connection.execute(
                "SELECT EXISTS(SELECT 1 FROM mizan.evidence_receipts "
                "WHERE tenant_id=%s AND stream_id=%s AND sequence_number=%s AND record_hash=%s)",
                (tenant_id, stream_id, sequence, record_hash),
            ).fetchone()[0]

    def receipt_rows(
        self, tenant_id: str, stream_id: str, start: int | None = None, end: int | None = None
    ) -> list[dict[str, Any]]:
        predicates, params = ["tenant_id=%s", "stream_id=%s"], [tenant_id, stream_id]
        if start is not None:
            predicates.append("sequence_number >= %s")
            params.append(start)
        if end is not None:
            predicates.append("sequence_number <= %s")
            params.append(end)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT signed_payload,signature FROM mizan.evidence_receipts WHERE "
                + " AND ".join(predicates)
                + " ORDER BY sequence_number",
                params,
            ).fetchall()
            return [{"payload": row[0], "signature": row[1]} for row in rows]

    def record_anchor(self, tenant_id: str, anchor: dict[str, Any], signature: str) -> None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            chain_head = connection.execute(
                "SELECT 1 FROM mizan.evidence_chain_heads "
                "WHERE tenant_id=%s AND stream_id=%s FOR UPDATE",
                (tenant_id, anchor["stream_id"]),
            ).fetchone()
            if not chain_head:
                raise Problem(404, "evidence_stream_missing", "Evidence stream does not exist")
            previous = connection.execute(
                "SELECT anchor_number,to_sequence,signed_payload FROM mizan.evidence_anchors "
                "WHERE tenant_id=%s AND stream_id=%s ORDER BY anchor_number DESC LIMIT 1",
                (tenant_id, anchor["stream_id"]),
            ).fetchone()
            expected_number = 0 if previous is None else previous[0] + 1
            expected_from = 0 if previous is None else previous[1] + 1
            expected_hash = "0" * 64 if previous is None else canonical_hash(previous[2])
            if (
                anchor["anchor_number"] != expected_number
                or anchor["from_sequence"] != expected_from
                or anchor["prev_anchor_hash"] != expected_hash
            ):
                raise Problem(
                    409,
                    "anchor_head_conflict",
                    "Anchor number, range, or previous hash lost the stream-head race",
                )
            connection.execute(
                """INSERT INTO mizan.evidence_anchors(
                     tenant_id,anchor_id,stream_id,from_sequence,to_sequence,head_hash,
                     prev_anchor_hash,anchor_number,covered_record_count,
                     object_version,object_key,key_id,signature,signed_payload
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    tenant_id,
                    anchor["anchor_id"],
                    anchor["stream_id"],
                    anchor["from_sequence"],
                    anchor["to_sequence"],
                    anchor["head_hash"],
                    anchor["prev_anchor_hash"],
                    anchor["anchor_number"],
                    anchor["covered_record_count"],
                    anchor["object_version"],
                    anchor["object_key"],
                    anchor["key_id"],
                    signature,
                    json.dumps(anchor),
                ),
            )

    def anchors(self, tenant_id: str, stream_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT signed_payload,signature,anchor_id FROM mizan.evidence_anchors "
                "WHERE tenant_id=%s AND stream_id=%s ORDER BY anchor_number NULLS FIRST,to_sequence",
                (tenant_id, stream_id),
            ).fetchall()
            result = []
            for row in rows:
                attestations = connection.execute(
                    "SELECT document FROM mizan.anchor_attestations "
                    "WHERE tenant_id=%s AND anchor_id=%s ORDER BY authority,attestation_type",
                    (tenant_id, row[2]),
                ).fetchall()
                result.append({
                    "payload": row[0],
                    "signature": row[1],
                    "attestations": [item[0] for item in attestations],
                })
            return result

    @contextmanager
    def lease_anchor_attestation(
        self, tenant_id: str, anchor_id: str
    ) -> Iterator[list[dict[str, Any]] | None]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            leased = connection.execute(
                "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0)) "
                "FROM mizan.evidence_anchors WHERE tenant_id=%s AND anchor_id=%s",
                (f"{tenant_id}:{anchor_id}:attestation", tenant_id, anchor_id),
            ).fetchone()
            if leased is None or not leased[0]:
                yield None
                return
            rows = connection.execute(
                "SELECT document FROM mizan.anchor_attestations "
                "WHERE tenant_id=%s AND anchor_id=%s ORDER BY authority,attestation_type",
                (tenant_id, anchor_id),
            ).fetchall()
            yield [row[0] for row in rows]

    def anchor_attestation(
        self,
        tenant_id: str,
        anchor_id: str,
        authority: str,
        attestation_type: str,
    ) -> dict[str, Any] | None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document FROM mizan.anchor_attestations "
                "WHERE tenant_id=%s AND anchor_id=%s AND authority=%s AND attestation_type=%s",
                (tenant_id, anchor_id, authority, attestation_type),
            ).fetchone()
            return None if row is None else row[0]

    def record_anchor_attestation(
        self, tenant_id: str, anchor_id: str, attestation: dict[str, Any]
    ) -> str:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            cursor = connection.execute(
                "INSERT INTO mizan.anchor_attestations(tenant_id,anchor_id,authority,attestation_type,document) "
                "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (
                    tenant_id,
                    anchor_id,
                    attestation["authority"],
                    attestation["type"],
                    json.dumps(attestation),
                ),
            )
            if cursor.rowcount == 1:
                return "appended"
            existing = connection.execute(
                "SELECT document FROM mizan.anchor_attestations "
                "WHERE tenant_id=%s AND anchor_id=%s AND authority=%s AND attestation_type=%s",
                (tenant_id, anchor_id, attestation["authority"], attestation["type"]),
            ).fetchone()
            if existing and existing[0] == attestation:
                return "unchanged"
            return "conflict"

    @staticmethod
    def _page_cursor(created_at: datetime, identifier: str) -> str:
        value = json.dumps([created_at.isoformat(), identifier], separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @staticmethod
    def _decode_page_cursor(cursor: str) -> tuple[datetime, str]:
        try:
            value = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
            timestamp, identifier = json.loads(value)
            return datetime.fromisoformat(timestamp), str(identifier)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise Problem(400, "invalid_cursor", "Pagination cursor is malformed") from exc

    def decision(self, tenant_id: str, decision_id: str) -> dict[str, Any]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            row = connection.execute(
                "SELECT document FROM mizan.adr_records WHERE tenant_id=%s AND decision_id=%s",
                (tenant_id, decision_id),
            ).fetchone()
            if not row:
                raise Problem(404, "decision_not_found", "Decision does not exist")
            events = connection.execute(
                "SELECT document FROM mizan.decision_events WHERE tenant_id=%s AND decision_id=%s "
                "ORDER BY decision_sequence",
                (tenant_id, decision_id),
            ).fetchall()
            return {"decision": row[0], "events": [item[0] for item in events]}

    def search_decisions(
        self,
        tenant_id: str,
        limit: int,
        cursor: str | None = None,
        **filters: Any,
    ) -> dict[str, Any]:
        clauses, params = ["tenant_id=%s"], [tenant_id]
        columns = {
            "agent_id": "agent_id",
            "tool_id": "tool_id",
            "decision": "decision",
            "risk": "document->'risk'->>'level'",
            "principal_id": "document->'principal'->>'id'",
            "customer_id": "document->'customer'->>'id'",
        }
        for name, column in columns.items():
            if filters.get(name):
                clauses.append(f"{column}=%s")
                params.append(filters[name])
        if filters.get("from_time"):
            clauses.append("created_at >= %s")
            params.append(filters["from_time"])
        if filters.get("to_time"):
            clauses.append("created_at <= %s")
            params.append(filters["to_time"])
        if cursor:
            created_at, identifier = self._decode_page_cursor(cursor)
            clauses.append("(created_at,decision_id) < (%s,%s)")
            params.extend([created_at, identifier])
        params.append(limit + 1)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT document,created_at,decision_id FROM mizan.adr_records WHERE "
                + " AND ".join(clauses)
                + " ORDER BY created_at DESC,decision_id DESC LIMIT %s",
                params,
            ).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = self._page_cursor(rows[-1][1], rows[-1][2]) if more else None
        return {"items": [row[0] for row in rows], "next_cursor": next_cursor}

    def dashboard_summary(self, tenant_id: str) -> dict[str, int]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            registry = connection.execute(
                "SELECT (SELECT count(*) FROM mizan.agents WHERE tenant_id=%s), "
                "(SELECT count(*) FROM mizan.tools WHERE tenant_id=%s)",
                (tenant_id, tenant_id),
            ).fetchone()
            actions = connection.execute(
                "SELECT count(*), count(*) FILTER (WHERE decision='DENY'), "
                "count(*) FILTER (WHERE decision='REQUIRE_APPROVAL'), "
                "count(*) FILTER (WHERE document->'risk'->>'level' IN ('HIGH','CRITICAL')) "
                "FROM mizan.adr_records WHERE tenant_id=%s "
                "AND created_at >= date_trunc('day', now())",
                (tenant_id,),
            ).fetchone()
            alerts = connection.execute(
                "SELECT count(*) FROM mizan.audit_trails WHERE tenant_id=%s "
                "AND occurred_at >= date_trunc('day', now()) "
                "AND document->>'event_type' LIKE 'mizan.security.%%'",
                (tenant_id,),
            ).fetchone()[0]
        return {
            "agents": registry[0],
            "tools": registry[1],
            "actions_today": actions[0],
            "denied_actions": actions[1],
            "approval_requests": actions[2],
            "security_alerts": alerts,
            "high_risk_actions": actions[3],
        }

    def search_audit(
        self,
        tenant_id: str,
        limit: int,
        cursor: str | None = None,
        event_type: str | None = None,
    ) -> dict[str, Any]:
        clauses, params = ["tenant_id=%s"], [tenant_id]
        if event_type:
            clauses.append("document->>'event_type'=%s")
            params.append(event_type)
        if cursor:
            occurred_at, identifier = self._decode_page_cursor(cursor)
            clauses.append("(occurred_at,audit_id) < (%s,%s)")
            params.extend([occurred_at, identifier])
        params.append(limit + 1)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT document,occurred_at,audit_id FROM mizan.audit_trails WHERE "
                + " AND ".join(clauses)
                + " ORDER BY occurred_at DESC,audit_id DESC LIMIT %s",
                params,
            ).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = self._page_cursor(rows[-1][1], rows[-1][2]) if more else None
        return {"items": [row[0] for row in rows], "next_cursor": next_cursor}


class OutboxPublisher:
    def __init__(
        self,
        repository: EvidenceRepository,
        store: LocalImmutableObjectStore,
        receipt_signer: Ed25519EvidenceSigner,
        anchor_signer: Ed25519EvidenceSigner,
        delivery: DeliverySink | None = None,
        anchor_provider: AnchorProvider | None = None,
    ) -> None:
        self.repository = repository
        self.store = store
        if receipt_signer.key_id == anchor_signer.key_id:
            raise ValueError("evidence receipt and anchor keys must be separately held")
        self.receipt_signer = receipt_signer
        self.anchor_signer = anchor_signer
        self.delivery = delivery or NullDeliverySink()
        self.anchor_provider = anchor_provider or anchor_provider_from_config()

    def drain(self, tenant_id: str, limit: int = 100) -> int:
        published = 0
        groups: dict[str, list[dict[str, Any]]] = {}
        for item in self.repository.unpublished(tenant_id, limit, evidence_only=True):
            groups.setdefault(item["payload"]["stream_id"], []).append(item)
        for stream_id, items in groups.items():
            items.sort(key=lambda item: item["payload"]["sequence_number"])
            first, last = items[0]["payload"], items[-1]["payload"]
            key = (
                f"segments/{tenant_id}/{stream_id.replace(':', '_')}/"
                f"{first['sequence_number']:020d}-{last['sequence_number']:020d}-{last['record_hash']}.json"
            )
            canonical = rfc8785.dumps([item["payload"] for item in items])
            object_version = self.store.put_once(key, canonical)
            for item in items:
                payload = item["payload"]
                receipt = {
                    "receipt_id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "stream_id": stream_id,
                    "sequence_number": payload["sequence_number"],
                    "record_hash": payload["record_hash"],
                    "object_version": object_version,
                    "object_key": key,
                    "key_id": self.receipt_signer.key_id,
                    "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
                signature = self.receipt_signer.sign(receipt)
                self.repository.record_publication(tenant_id, item["outbox_id"], receipt, signature)
                self.delivery.publish(item["event_type"], stream_id, payload)
                published += 1
        return published

    def anchor(
        self, tenant_id: str, stream_id: str, from_sequence: int | None = None
    ) -> dict[str, Any]:
        prior = self.repository.anchors(tenant_id, stream_id)
        previous_payload = prior[-1]["payload"] if prior else None
        expected_from = 0 if previous_payload is None else previous_payload["to_sequence"] + 1
        if from_sequence is not None and from_sequence != expected_from:
            raise Problem(409, "anchor_range_not_dense", "Anchor range must continue the prior anchor")
        from_sequence = expected_from
        receipts = self.repository.receipt_rows(tenant_id, stream_id, from_sequence)
        if not receipts:
            raise Problem(
                404, "evidence_range_empty", "No published records are available to anchor"
            )
        last = receipts[-1]["payload"]
        key = (
            f"anchors/{tenant_id}/{stream_id.replace(':', '_')}/{last['sequence_number']:020d}.json"
        )
        anchor_core = {
            "anchor_id": str(uuid4()),
            "tenant_id": tenant_id,
            "stream_id": stream_id,
            "anchor_number": 0 if previous_payload is None else previous_payload["anchor_number"] + 1,
            "prev_anchor_hash": (
                "0" * 64 if previous_payload is None else canonical_hash(previous_payload)
            ),
            "from_sequence": from_sequence,
            "to_sequence": last["sequence_number"],
            "covered_record_count": len(receipts),
            "head_hash": last["record_hash"],
            "key_id": self.anchor_signer.key_id,
            "anchored_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        proposed = self.anchor_provider.attest(anchor_core)
        unsigned = anchor_core | {
            "attestations": proposed if isinstance(proposed, list) else [proposed]
        }
        object_version = self.store.put_once(key, rfc8785.dumps(unsigned))
        anchor = unsigned | {"object_key": key, "object_version": object_version}
        signature = self.anchor_signer.sign(anchor)
        self.repository.record_anchor(tenant_id, anchor, signature)
        return anchor | {"signature": signature}


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    checked_records: int
    first_broken_sequence: int | None = None
    expected: str | None = None
    actual: str | None = None


def verify_anchor_chain(
    anchor_rows: list[dict[str, Any]], records: list[dict[str, Any]] | None = None
) -> VerificationResult:
    ordered = sorted(
        anchor_rows,
        key=lambda row: row.get("payload", {}).get("anchor_number", -1),
    )
    expected_previous = "0" * 64
    expected_from = 0
    for expected_number, row in enumerate(ordered):
        payload = row.get("payload", {})
        required = {
            "anchor_number", "prev_anchor_hash", "from_sequence", "to_sequence",
            "covered_record_count", "head_hash",
        }
        missing = required - set(payload)
        if missing:
            return VerificationResult(False, 0, None, "anchor chain metadata", f"missing {sorted(missing)}")
        if payload["anchor_number"] != expected_number:
            return VerificationResult(
                False, 0, payload["from_sequence"],
                f"anchor_number {expected_number}", f"anchor_number {payload['anchor_number']}",
            )
        if payload["prev_anchor_hash"] != expected_previous:
            return VerificationResult(
                False, 0, payload["from_sequence"], expected_previous, payload["prev_anchor_hash"]
            )
        if payload["from_sequence"] != expected_from:
            return VerificationResult(
                False, 0, payload["from_sequence"],
                f"from_sequence {expected_from}", f"from_sequence {payload['from_sequence']}",
            )
        range_count = payload["to_sequence"] - payload["from_sequence"] + 1
        if payload["covered_record_count"] != range_count:
            return VerificationResult(
                False, 0, payload["from_sequence"],
                f"covered_record_count {range_count}",
                f"covered_record_count {payload['covered_record_count']}",
            )
        if records is not None:
            covered = [
                record for record in records
                if payload["from_sequence"] <= record["sequence_number"] <= payload["to_sequence"]
            ]
            if len(covered) != payload["covered_record_count"]:
                return VerificationResult(
                    False, len(covered), payload["from_sequence"],
                    f"covered_record_count {payload['covered_record_count']}",
                    f"covered records {len(covered)}",
                )
            if covered and covered[-1]["record_hash"] != payload["head_hash"]:
                return VerificationResult(
                    False, len(covered), payload["to_sequence"],
                    payload["head_hash"], covered[-1]["record_hash"],
                )
        expected_from = payload["to_sequence"] + 1
        expected_previous = canonical_hash(payload)
    if records:
        if not ordered:
            return VerificationResult(
                False,
                len(records),
                records[-1]["sequence_number"],
                "signed anchor covering verified range",
                "no covering anchor",
            )
        current = ordered[-1]["payload"]
        if current["to_sequence"] != records[-1]["sequence_number"]:
            return VerificationResult(
                False, len(records), records[-1]["sequence_number"],
                f"current anchor through {records[-1]['sequence_number']}",
                f"stale anchor through {current['to_sequence']}",
            )
    return VerificationResult(True, 0 if records is None else len(records))


@dataclass(frozen=True, slots=True)
class ChainCheckpoint:
    from_sequence: int
    to_sequence: int
    expected_previous: str
    head_hash: str


def verify_chain(
    records: list[dict[str, Any]], expected_previous: str | None = None
) -> VerificationResult:
    previous = expected_previous
    prior_sequence: int | None = None
    for record in records:
        sequence = record["sequence_number"]
        if prior_sequence is not None and sequence != prior_sequence + 1:
            return VerificationResult(
                valid=False,
                checked_records=0 if prior_sequence is None else prior_sequence + 1,
                first_broken_sequence=sequence,
                expected=str(prior_sequence + 1),
                actual=str(sequence),
            )
        if previous is not None and record["prev_hash"] != previous:
            return VerificationResult(False, 0, sequence, previous, record["prev_hash"])
        actual = canonical_hash(
            {key: value for key, value in record.items() if key != "record_hash"}
        )
        if actual != record["record_hash"]:
            return VerificationResult(False, sequence, sequence, record["record_hash"], actual)
        previous, prior_sequence = record["record_hash"], sequence
    return VerificationResult(True, len(records))


def verify_checkpointed_chain(
    records: list[dict[str, Any]],
    checkpoints: list[ChainCheckpoint],
    workers: int = 4,
) -> VerificationResult:
    """Verify independently anchored ranges concurrently without trusting adjacent records."""
    if not checkpoints:
        return VerificationResult(
            not records, 0, None if not records else records[0]["sequence_number"]
        )
    ordered = sorted(checkpoints, key=lambda item: item.from_sequence)
    record_by_sequence = {record["sequence_number"]: record for record in records}
    if len(record_by_sequence) != len(records):
        return VerificationResult(False, 0, None, "unique sequence numbers", "duplicate")
    prior_end: int | None = None
    ranges: list[tuple[ChainCheckpoint, list[dict[str, Any]]]] = []
    prior_head: str | None = None
    for checkpoint in ordered:
        if checkpoint.to_sequence < checkpoint.from_sequence:
            return VerificationResult(
                False, 0, checkpoint.from_sequence, "non-empty range", "empty"
            )
        if prior_end is not None and checkpoint.from_sequence != prior_end + 1:
            return VerificationResult(
                False,
                0,
                checkpoint.from_sequence,
                str(prior_end + 1),
                str(checkpoint.from_sequence),
            )
        if prior_head is not None and checkpoint.expected_previous != prior_head:
            return VerificationResult(
                False, 0, checkpoint.from_sequence, prior_head, checkpoint.expected_previous
            )
        selected = [
            record_by_sequence[sequence]
            for sequence in range(checkpoint.from_sequence, checkpoint.to_sequence + 1)
            if sequence in record_by_sequence
        ]
        expected_count = checkpoint.to_sequence - checkpoint.from_sequence + 1
        if len(selected) != expected_count:
            return VerificationResult(
                False, 0, checkpoint.from_sequence, str(expected_count), str(len(selected))
            )
        ranges.append((checkpoint, selected))
        prior_end = checkpoint.to_sequence
        prior_head = checkpoint.head_hash
    covered = sum(len(group) for _, group in ranges)
    if covered != len(records):
        return VerificationResult(False, 0, None, str(covered), str(len(records)))

    def verify_range(item: tuple[ChainCheckpoint, list[dict[str, Any]]]) -> VerificationResult:
        checkpoint, group = item
        result = verify_chain(group, checkpoint.expected_previous)
        if result.valid and group[-1]["record_hash"] != checkpoint.head_hash:
            return VerificationResult(
                False,
                len(group),
                checkpoint.to_sequence,
                checkpoint.head_hash,
                group[-1]["record_hash"],
            )
        return result

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ranges)))) as executor:
        results = list(executor.map(verify_range, ranges))
    for result in results:
        if not result.valid:
            return result
    return VerificationResult(True, sum(result.checked_records for result in results))


class ObjectEvidenceVerifier:
    def __init__(
        self,
        repository: EvidenceRepository,
        store: LocalImmutableObjectStore,
        public_keys: dict[str, Ed25519PublicKey],
        checkpoint_interval: int = 1000,
        workers: int = 4,
    ) -> None:
        self.repository = repository
        self.store = store
        self.public_keys = public_keys
        if checkpoint_interval < 1 or workers < 1:
            raise ValueError("verification checkpoint interval and worker count must be positive")
        self.checkpoint_interval = checkpoint_interval
        self.workers = workers

    def verify(
        self,
        tenant_id: str,
        stream_id: str,
        start: int | None = None,
        end: int | None = None,
        verify_anchors: bool = True,
    ) -> VerificationResult:
        receipts = self.repository.receipt_rows(tenant_id, stream_id, start, end)
        records_by_sequence: dict[int, dict[str, Any]] = {}
        objects: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for receipt in receipts:
            payload = receipt["payload"]
            if payload["key_id"] not in self.public_keys:
                raise Problem(409, "evidence_key_unknown", "Receipt signing key is unavailable")
            object_identity = payload["object_key"], payload["object_version"]
            objects.setdefault(object_identity, []).append(payload)

        def verify_receipt_group(group: list[dict[str, Any]]) -> dict[str, Any] | None:
            for receipt in group:
                payload = receipt["payload"]
                try:
                    verify_signature(
                        payload, receipt["signature"], self.public_keys[payload["key_id"]]
                    )
                except Exception:
                    return payload
            return None

        chunk_size = max(1, (len(receipts) + self.workers - 1) // self.workers)
        receipt_groups = [
            receipts[offset : offset + chunk_size] for offset in range(0, len(receipts), chunk_size)
        ]
        with ThreadPoolExecutor(
            max_workers=min(self.workers, len(receipt_groups) or 1)
        ) as executor:
            invalid_receipts = [
                item for item in executor.map(verify_receipt_group, receipt_groups) if item
            ]
        if invalid_receipts:
            payload = min(invalid_receipts, key=lambda item: item["sequence_number"])
            return VerificationResult(
                False,
                0,
                payload["sequence_number"],
                "valid receipt signature",
                "invalid signature",
            )
        for (object_key, object_version), object_receipts in objects.items():
            try:
                raw = self.store.get(object_key)
            except (FileNotFoundError, OSError):
                return VerificationResult(
                    False,
                    len(records_by_sequence),
                    object_receipts[0]["sequence_number"],
                    object_version,
                    "object missing",
                )
            actual_version = canonical_hash(
                {
                    "key": object_key,
                    "payload_sha256": canonical_hash_bytes(raw),
                }
            )
            if actual_version != object_version:
                return VerificationResult(
                    False,
                    len(records_by_sequence),
                    object_receipts[0]["sequence_number"],
                    object_version,
                    actual_version,
                )
            try:
                stored = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                return VerificationResult(
                    False,
                    len(records_by_sequence),
                    object_receipts[0]["sequence_number"],
                    "canonical JSON segment",
                    "malformed object",
                )
            candidates = stored if isinstance(stored, list) else [stored]
            indexed: dict[tuple[int, str], list[dict[str, Any]]] = {}
            for record in candidates:
                indexed.setdefault((record["sequence_number"], record["record_hash"]), []).append(
                    record
                )
            for payload in object_receipts:
                matches = indexed.get((payload["sequence_number"], payload["record_hash"]), [])
                if len(matches) != 1 or payload["sequence_number"] in records_by_sequence:
                    return VerificationResult(
                        False,
                        len(records_by_sequence),
                        payload["sequence_number"],
                        payload["record_hash"],
                        "missing-or-duplicate",
                    )
                records_by_sequence[payload["sequence_number"]] = matches[0]
        records = [records_by_sequence[sequence] for sequence in sorted(records_by_sequence)]
        if records:
            expected_first = 0 if start is None else start
            if records[0]["sequence_number"] != expected_first:
                return VerificationResult(
                    False,
                    0,
                    records[0]["sequence_number"],
                    str(expected_first),
                    str(records[0]["sequence_number"]),
                )
            if expected_first == 0 and records[0]["prev_hash"] != "0" * 64:
                return VerificationResult(
                    False,
                    0,
                    0,
                    "0" * 64,
                    records[0]["prev_hash"],
                )
            if end is not None and records[-1]["sequence_number"] != end:
                return VerificationResult(
                    False,
                    len(records),
                    end,
                    str(end),
                    str(records[-1]["sequence_number"]),
                )
        elif start is not None or end is not None:
            return VerificationResult(False, 0, start, "non-empty evidence range", "empty")
        checkpoints: list[ChainCheckpoint] = []
        for offset in range(0, len(records), self.checkpoint_interval):
            group = records[offset : offset + self.checkpoint_interval]
            checkpoints.append(
                ChainCheckpoint(
                    group[0]["sequence_number"],
                    group[-1]["sequence_number"],
                    group[0]["prev_hash"],
                    group[-1]["record_hash"],
                )
            )
        result = verify_checkpointed_chain(records, checkpoints, self.workers)
        if not result.valid or not verify_anchors:
            return result
        verified_anchor_rows: list[dict[str, Any]] = []
        for anchor_row in self.repository.anchors(tenant_id, stream_id):
            payload = anchor_row["payload"]
            key = self.public_keys.get(payload["key_id"])
            if key is None:
                raise Problem(409, "evidence_key_unknown", "Anchor signing key is unavailable")
            try:
                verify_signature(payload, anchor_row["signature"], key)
                raw_anchor = self.store.get(payload["object_key"])
            except Exception:
                return VerificationResult(
                    False,
                    len(records),
                    payload["to_sequence"],
                    "valid anchor signature and WORM object",
                    "invalid or missing anchor",
                )
            actual_version = canonical_hash(
                {
                    "key": payload["object_key"],
                    "payload_sha256": canonical_hash_bytes(raw_anchor),
                }
            )
            if actual_version != payload["object_version"]:
                return VerificationResult(
                    False,
                    len(records),
                    payload["to_sequence"],
                    payload["object_version"],
                    actual_version,
                )
            unsigned = {
                key: value
                for key, value in payload.items()
                if key not in {"object_key", "object_version"}
            }
            if raw_anchor != rfc8785.dumps(unsigned):
                return VerificationResult(
                    False,
                    len(records),
                    payload["to_sequence"],
                    "signed anchor payload",
                    "anchor object mismatch",
                )
            verified_anchor_rows.append(anchor_row)
        anchor_result = verify_anchor_chain(
            verified_anchor_rows,
            records if start is None and end is None else None,
        )
        if not anchor_result.valid:
            return anchor_result
        return result

    def verify_record_receipt(
        self, tenant_id: str, stream_id: str, sequence_number: int, record_hash: str
    ) -> bool:
        result = self.verify(
            tenant_id, stream_id, sequence_number, sequence_number, verify_anchors=False
        )
        if not result.valid:
            return False
        receipts = self.repository.receipt_rows(
            tenant_id, stream_id, sequence_number, sequence_number
        )
        return len(receipts) == 1 and receipts[0]["payload"]["record_hash"] == record_hash
