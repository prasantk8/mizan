from __future__ import annotations

import copy
from pathlib import Path

import pytest
import rfc8785
from cryptography.exceptions import InvalidSignature
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import (
    ChainCheckpoint,
    Ed25519EvidenceSigner,
    LocalImmutableObjectStore,
    ObjectEvidenceVerifier,
    verify_chain,
    verify_checkpointed_chain,
    verify_signature,
)


def record(sequence: int, previous: str, value: str) -> dict:
    document = {
        "tenant_id": "tnt_bank-a",
        "stream_id": "tnt_bank-a:adr:0",
        "sequence_number": sequence,
        "prev_hash": previous,
        "value": value,
    }
    document["record_hash"] = canonical_hash(document)
    return document


def test_chain_verifier_detects_payload_tampering_and_gaps() -> None:
    first = record(0, "0" * 64, "first")
    second = record(1, first["record_hash"], "second")
    assert verify_chain([first, second], "0" * 64).valid
    tampered = copy.deepcopy(second)
    tampered["value"] = "rewritten"
    result = verify_chain([first, tampered], "0" * 64)
    assert not result.valid and result.first_broken_sequence == 1
    gap = record(2, first["record_hash"], "gap")
    assert not verify_chain([first, gap], "0" * 64).valid


def test_local_object_store_is_create_only(tmp_path: Path) -> None:
    store = LocalImmutableObjectStore(tmp_path)
    version = store.put_once("records/a.json", b"first")
    assert store.put_once("records/a.json", b"first") == version
    with pytest.raises(RuntimeError, match="collision"):
        store.put_once("records/a.json", b"rewritten")


def test_receipt_signatures_detect_mutation() -> None:
    signer = Ed25519EvidenceSigner.generate()
    payload = {"tenant_id": "tnt_bank-a", "record_hash": "a" * 64}
    signature = signer.sign(payload)
    verify_signature(payload, signature, signer.public_key)
    with pytest.raises(InvalidSignature):
        verify_signature(payload | {"record_hash": "b" * 64}, signature, signer.public_key)


def test_checkpointed_parallel_verifier_detects_corruption() -> None:
    records: list[dict] = []
    checkpoints: list[ChainCheckpoint] = []
    previous = "0" * 64
    for start in range(0, 100, 10):
        expected_previous = previous
        for sequence in range(start, start + 10):
            item = record(sequence, previous, f"value-{sequence}")
            records.append(item)
            previous = item["record_hash"]
        checkpoints.append(ChainCheckpoint(start, start + 9, expected_previous, previous))
    result = verify_checkpointed_chain(records, checkpoints, workers=4)
    assert result.valid and result.checked_records == 100
    corrupted = copy.deepcopy(records)
    corrupted[55]["value"] = "tampered"
    result = verify_checkpointed_chain(corrupted, checkpoints, workers=4)
    assert not result.valid and result.first_broken_sequence == 55
    discontinuous = list(checkpoints)
    discontinuous[3] = ChainCheckpoint(30, 39, "f" * 64, discontinuous[3].head_hash)
    result = verify_checkpointed_chain(records, discontinuous, workers=4)
    assert not result.valid and result.first_broken_sequence == 30


class FakeEvidenceRepository:
    def __init__(self, receipts: list[dict], anchors: list[dict]) -> None:
        self.receipt_data = receipts
        self.anchor_data = anchors

    def receipt_rows(self, tenant_id, stream_id, start=None, end=None):
        return [
            item
            for item in self.receipt_data
            if (start is None or item["payload"]["sequence_number"] >= start)
            and (end is None or item["payload"]["sequence_number"] <= end)
        ]

    def anchors(self, tenant_id, stream_id):
        return self.anchor_data


class CountingStore(LocalImmutableObjectStore):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.reads = 0

    def get(self, key: str) -> bytes:
        self.reads += 1
        return super().get(key)


def test_object_verifier_deduplicates_segments_and_requires_worm_anchor(tmp_path: Path) -> None:
    signer = Ed25519EvidenceSigner.generate()
    store = CountingStore(tmp_path)
    records, previous = [], "0" * 64
    for sequence in range(10):
        item = record(sequence, previous, f"value-{sequence}")
        records.append(item)
        previous = item["record_hash"]
    segment_key = "segments/tnt_bank-a/stream/0-9.json"
    segment_version = store.put_once(segment_key, rfc8785.dumps(records))
    receipts = []
    for item in records:
        payload = {
            "tenant_id": "tnt_bank-a",
            "stream_id": "tnt_bank-a:adr:0",
            "sequence_number": item["sequence_number"],
            "record_hash": item["record_hash"],
            "object_key": segment_key,
            "object_version": segment_version,
            "key_id": signer.key_id,
        }
        receipts.append({"payload": payload, "signature": signer.sign(payload)})
    unsigned_anchor = {
        "anchor_id": "anchor-1",
        "tenant_id": "tnt_bank-a",
        "stream_id": "tnt_bank-a:adr:0",
        "from_sequence": 0,
        "to_sequence": 9,
        "head_hash": previous,
        "key_id": signer.key_id,
        "anchored_at": "2026-08-25T00:00:00Z",
    }
    anchor_key = "anchors/tnt_bank-a/stream/9.json"
    anchor_version = store.put_once(anchor_key, rfc8785.dumps(unsigned_anchor))
    anchor = unsigned_anchor | {"object_key": anchor_key, "object_version": anchor_version}
    repository = FakeEvidenceRepository(
        receipts,
        [{"payload": anchor, "signature": signer.sign(anchor)}],
    )
    verifier = ObjectEvidenceVerifier(repository, store, {signer.key_id: signer.public_key}, 3, 3)
    result = verifier.verify("tnt_bank-a", "tnt_bank-a:adr:0")
    assert result.valid and result.checked_records == 10
    assert store.reads == 2  # one segment read, not one read per receipt, plus one anchor
    repository.anchor_data = []
    result = verifier.verify("tnt_bank-a", "tnt_bank-a:adr:0")
    assert not result.valid and result.actual == "no covering anchor"
