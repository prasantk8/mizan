from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from mizan_control_plane.canonical import canonical_hash
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    LocalImmutableObjectStore,
    verify_chain,
    verify_signature,
)


def record(sequence: int, previous: str, value: str) -> dict:
    document = {
        "tenant_id": "tnt_bank-a", "stream_id": "tnt_bank-a:adr:0",
        "sequence_number": sequence, "prev_hash": previous, "value": value,
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
