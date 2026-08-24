from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import (
    ChainCheckpoint,
    Ed25519EvidenceSigner,
    LocalImmutableObjectStore,
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
