from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from psycopg_pool import ConnectionPool

from .canonical import canonical_hash
from .problems import Problem


class DeliverySink(Protocol):
    def publish(self, event_type: str, key: str, payload: dict[str, Any]) -> None: ...


class NullDeliverySink:
    def publish(self, event_type: str, key: str, payload: dict[str, Any]) -> None:
        return None


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
    key_id: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, key_id: str = "local://evidence/dev-1") -> Ed25519EvidenceSigner:
        return cls(key_id=key_id, private_key=Ed25519PrivateKey.generate())

    def sign(self, payload: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(self.private_key.sign(rfc8785.dumps(payload))).decode()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()


def verify_signature(payload: dict[str, Any], signature: str, key: Ed25519PublicKey) -> None:
    key.verify(base64.urlsafe_b64decode(signature), rfc8785.dumps(payload))


def append_decision_event_tx(
    connection: Any, tenant_id: str, decision_id: str, event_type: str,
    actor: dict[str, Any], payload: dict[str, Any], occurred_at: datetime,
) -> dict[str, Any]:
    adr = connection.execute(
        "SELECT stream_id FROM mizan.adr_records WHERE tenant_id=%s AND decision_id=%s",
        (tenant_id, decision_id),
    ).fetchone()
    if not adr:
        raise Problem(404, "decision_not_found", "Decision does not exist")
    stream_id = adr[0]
    connection.execute(
        "INSERT INTO mizan.decision_event_heads(tenant_id,decision_id) VALUES (%s,%s) "
        "ON CONFLICT DO NOTHING", (tenant_id, decision_id),
    )
    event_head = connection.execute(
        "SELECT next_sequence,last_hash FROM mizan.decision_event_heads "
        "WHERE tenant_id=%s AND decision_id=%s FOR UPDATE", (tenant_id, decision_id),
    ).fetchone()
    evidence_head = connection.execute(
        "SELECT next_sequence,last_hash FROM mizan.evidence_chain_heads "
        "WHERE tenant_id=%s AND stream_id=%s FOR UPDATE", (tenant_id, stream_id),
    ).fetchone()
    event_id = "dev_" + uuid4().hex
    document = {
        "schema_version": "1.2", "event_id": event_id, "tenant_id": tenant_id,
        "decision_id": decision_id, "decision_sequence": event_head[0],
        "previous_event_hash": None if event_head[0] == 1 else event_head[1],
        "event_type": event_type, "actor": actor,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"), "payload": payload,
        "stream_id": stream_id, "sequence_number": evidence_head[0],
        "prev_hash": evidence_head[1], "record_hash": "0" * 64,
        "hash_alg": "SHA-256", "canonicalization": "RFC8785", "immutable_receipt_ref": None,
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
        document["decision_sequence"], document["sequence_number"],
    ):
        raise RuntimeError("DecisionEvent sequence allocation mismatch")
    connection.execute(
        """INSERT INTO mizan.decision_events(
             tenant_id,event_id,decision_id,decision_sequence,event_type,previous_event_hash,
             event_hash,stream_id,sequence_number,prev_hash,record_hash,document,occurred_at
           ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (tenant_id,event_id,decision_id,event_sequence,event_type,event_head[1],document["record_hash"],
         stream_id,evidence_sequence,evidence_head[1],document["record_hash"],json.dumps(document),occurred_at),
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

    def unpublished(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                """SELECT outbox_id,event_type,payload,created_at
                     FROM mizan.outbox WHERE tenant_id=%s AND published_at IS NULL
                     ORDER BY outbox_id LIMIT %s FOR UPDATE SKIP LOCKED""",
                (tenant_id, limit),
            ).fetchall()
            return [
                {"outbox_id": row[0], "event_type": row[1], "payload": row[2], "created_at": row[3]}
                for row in rows
            ]

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
                (tenant_id,receipt["receipt_id"],receipt["stream_id"],receipt["sequence_number"],
                 receipt["record_hash"],receipt["object_version"],receipt["object_key"],
                 receipt["key_id"],signature,json.dumps(receipt)),
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
                "SELECT document,sequence_number FROM mizan.adr_records WHERE " + where
                + " UNION ALL SELECT document,(document->>'sequence_number')::bigint "
                "FROM mizan.decision_events WHERE " + where
                + " ORDER BY sequence_number"
            )
            return [row[0] for row in connection.execute(query, [*params, *params]).fetchall()]

    def append_decision_event(
        self, tenant_id: str, decision_id: str, event_type: str,
        actor: dict[str, Any], payload: dict[str, Any], occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        occurred_at = occurred_at or datetime.now(UTC)
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            return append_decision_event_tx(
                connection, tenant_id, decision_id, event_type, actor, payload, occurred_at,
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
                + " AND ".join(predicates) + " ORDER BY sequence_number", params,
            ).fetchall()
            return [{"payload": row[0], "signature": row[1]} for row in rows]

    def record_anchor(self, tenant_id: str, anchor: dict[str, Any], signature: str) -> None:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            connection.execute(
                """INSERT INTO mizan.evidence_anchors(
                     tenant_id,anchor_id,stream_id,from_sequence,to_sequence,head_hash,
                     object_version,object_key,key_id,signature,signed_payload
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (tenant_id,anchor["anchor_id"],anchor["stream_id"],anchor["from_sequence"],
                 anchor["to_sequence"],anchor["head_hash"],anchor["object_version"],
                 anchor["object_key"],anchor["key_id"],signature,json.dumps(anchor)),
            )

    def anchors(self, tenant_id: str, stream_id: str) -> list[dict[str, Any]]:
        with self.pool.connection() as connection, connection.transaction():
            self._scope(connection, tenant_id)
            rows = connection.execute(
                "SELECT signed_payload,signature FROM mizan.evidence_anchors "
                "WHERE tenant_id=%s AND stream_id=%s ORDER BY to_sequence",
                (tenant_id, stream_id),
            ).fetchall()
            return [{"payload": row[0], "signature": row[1]} for row in rows]


class OutboxPublisher:
    def __init__(self, repository: EvidenceRepository, store: LocalImmutableObjectStore,
                 signer: Ed25519EvidenceSigner, delivery: DeliverySink | None = None) -> None:
        self.repository = repository
        self.store = store
        self.signer = signer
        self.delivery = delivery or NullDeliverySink()

    def drain(self, tenant_id: str, limit: int = 100) -> int:
        published = 0
        groups: dict[str, list[dict[str, Any]]] = {}
        for item in self.repository.unpublished(tenant_id, limit):
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
                    "receipt_id": str(uuid4()), "tenant_id": tenant_id, "stream_id": stream_id,
                    "sequence_number": payload["sequence_number"], "record_hash": payload["record_hash"],
                    "object_version": object_version, "object_key": key, "key_id": self.signer.key_id,
                    "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
                signature = self.signer.sign(receipt)
                self.repository.record_publication(tenant_id, item["outbox_id"], receipt, signature)
                self.delivery.publish(item["event_type"], stream_id, payload)
                published += 1
        return published

    def anchor(self, tenant_id: str, stream_id: str, from_sequence: int = 0) -> dict[str, Any]:
        receipts = self.repository.receipt_rows(tenant_id, stream_id, from_sequence)
        if not receipts:
            raise Problem(404, "evidence_range_empty", "No published records are available to anchor")
        last = receipts[-1]["payload"]
        key = f"anchors/{tenant_id}/{stream_id.replace(':', '_')}/{last['sequence_number']:020d}.json"
        unsigned = {
            "anchor_id": str(uuid4()), "tenant_id": tenant_id, "stream_id": stream_id,
            "from_sequence": from_sequence, "to_sequence": last["sequence_number"],
            "head_hash": last["record_hash"], "key_id": self.signer.key_id,
            "anchored_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        object_version = self.store.put_once(key, rfc8785.dumps(unsigned))
        anchor = unsigned | {"object_key": key, "object_version": object_version}
        signature = self.signer.sign(anchor)
        self.repository.record_anchor(tenant_id, anchor, signature)
        return anchor | {"signature": signature}


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    checked_records: int
    first_broken_sequence: int | None = None
    expected: str | None = None
    actual: str | None = None


def verify_chain(records: list[dict[str, Any]], expected_previous: str | None = None) -> VerificationResult:
    previous = expected_previous
    prior_sequence: int | None = None
    for record in records:
        sequence = record["sequence_number"]
        if prior_sequence is not None and sequence != prior_sequence + 1:
            return VerificationResult(
                valid=False, checked_records=0 if prior_sequence is None else prior_sequence + 1,
                first_broken_sequence=sequence, expected=str(prior_sequence + 1), actual=str(sequence),
            )
        if previous is not None and record["prev_hash"] != previous:
            return VerificationResult(False, 0, sequence, previous, record["prev_hash"])
        actual = canonical_hash({key: value for key, value in record.items() if key != "record_hash"})
        if actual != record["record_hash"]:
            return VerificationResult(False, sequence, sequence, record["record_hash"], actual)
        previous, prior_sequence = record["record_hash"], sequence
    return VerificationResult(True, len(records))


class ObjectEvidenceVerifier:
    def __init__(self, repository: EvidenceRepository, store: LocalImmutableObjectStore,
                 public_keys: dict[str, Ed25519PublicKey]) -> None:
        self.repository = repository
        self.store = store
        self.public_keys = public_keys

    def verify(self, tenant_id: str, stream_id: str, start: int | None = None,
               end: int | None = None, verify_anchors: bool = True) -> VerificationResult:
        receipts = self.repository.receipt_rows(tenant_id, stream_id, start, end)
        records: list[dict[str, Any]] = []
        for receipt in receipts:
            payload = receipt["payload"]
            key = self.public_keys.get(payload["key_id"])
            if key is None:
                raise Problem(409, "evidence_key_unknown", "Receipt signing key is unavailable")
            verify_signature(payload, receipt["signature"], key)
            raw = self.store.get(payload["object_key"])
            actual_version = canonical_hash({
                "key": payload["object_key"], "payload_sha256": canonical_hash_bytes(raw),
            })
            if actual_version != payload["object_version"]:
                return VerificationResult(False, len(records), payload["sequence_number"],
                                          payload["object_version"], actual_version)
            stored = json.loads(raw)
            candidates = stored if isinstance(stored, list) else [stored]
            matches = [
                record for record in candidates
                if record["sequence_number"] == payload["sequence_number"]
                and record["record_hash"] == payload["record_hash"]
            ]
            if len(matches) != 1:
                return VerificationResult(False, len(records), payload["sequence_number"],
                                          payload["record_hash"], "missing-or-duplicate")
            record = matches[0]
            if record["record_hash"] != payload["record_hash"]:
                return VerificationResult(False, len(records), record["sequence_number"],
                                          payload["record_hash"], record["record_hash"])
            records.append(record)
        result = verify_chain(records, "0" * 64 if start in {None, 0} else None)
        if not result.valid or not verify_anchors:
            return result
        for anchor_row in self.repository.anchors(tenant_id, stream_id):
            payload = anchor_row["payload"]
            key = self.public_keys.get(payload["key_id"])
            if key is None:
                raise Problem(409, "evidence_key_unknown", "Anchor signing key is unavailable")
            verify_signature(payload, anchor_row["signature"], key)
            anchored = [record for record in records if record["sequence_number"] == payload["to_sequence"]]
            if anchored and anchored[0]["record_hash"] != payload["head_hash"]:
                return VerificationResult(False, len(records), payload["to_sequence"],
                                          payload["head_hash"], anchored[0]["record_hash"])
        return result
