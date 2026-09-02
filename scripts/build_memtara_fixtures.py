#!/usr/bin/env python3
"""Rebuild the cross-anchored Memtara conformance bundles (bundle format 1.1, section 2.1).

Not a gate and not run by CI. It exists so the committed proof-bearing fixtures are reproducible
byte for byte, and so the reason each one exists is written down next to the code that builds it.

    uv run --frozen python scripts/build_memtara_fixtures.py

Why a generator and not three hand-edited directories. Section 5 orders the verification phases:
the manifest `files` digests are checked in phase 3, before any of the bundle grammar in phase 4
and long before the external-proof evidence checks at the end. A fixture produced by opening
`records.json` in an editor therefore stops at "records.json checksum mismatch" and says exactly
nothing about the proof code -- it would be a green test that never executes the lines it claims
to cover, which is the defect this task exists to remove. So every bundle here is built from the
inside out: the records, then the record hash/prev_hash chain over them, then the receipt
signatures over those hashes, then the anchor over the terminal record, then the manifest digests
over the stored bytes. Change one byte of a proof and everything downstream is recomputed, so the
run reaches the binding check with an otherwise flawless bundle in front of it.

Three bundles, and the difference between them is the whole point:

  valid-memtara-proof/            Two records carry a Memtara proof; two carry the empty array
                                  section 2.1 requires of any schema-1.3 record with nothing to
                                  report. With the operator's JWKS this is VALID; with no JWKS the
                                  same bytes are CANNOT CHECK, because trust roots are supplied by
                                  the operator and MUST NOT come from the bundle. Both verdicts are
                                  in the corpus against this one directory: the pair is the claim.
  invalid-memtara-proof-binding/  Identical, except one record's `proof_hash` states a digest the
                                  signed Memtara token does not. The token signature still
                                  verifies, the record hash commits the tampered value, the chain,
                                  the receipts, the anchor and the manifest are all recomputed
                                  around it -- so nothing else in the bundle is wrong and the only
                                  check that can catch it is the projection-to-claim binding
                                  (`verify_evidence_export.verify_external_proofs`, the
                                  `("proof_hash", "proof_hash")` pair; `checkExternalProofs` in
                                  verifier-two/lib/verify.js). INVALID, never MALFORMED.
  malformed-memtara-in-1.0/       The same proof-bearing records under a manifest that declares
                                  `bundle_version` "1.0". Section 2.1: a 1.0 bundle MUST NOT carry
                                  the member, so a 1.0-only verifier fails loudly instead of
                                  silently ignoring evidence it does not understand. Its digests
                                  are correct, so it reaches the phase-4 grammar that refuses it.

Determinism. The Memtara signing key is derived from a pinned seed and the Mizan receipt/anchor
keys are the repository's development keys (private half = `sha256(key_id)`, see
`control-plane/mizan_control_plane/keys.py`). Every timestamp, identifier and payload below is a
literal. Ed25519 is deterministic (RFC 8032) and every document is written with RFC 8785, so
re-running this script reproduces the committed bytes exactly. `git status` after a rebuild is the
test of that claim.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CORPUS = Path("tests/fixtures/conformance")
TRUST_ROOT = CORPUS / "memtara-trust-root.jwks.json"

# Pinned. Regenerating this constant would rotate the committed JWKS and invalidate every token in
# every fixture, so it is a literal rather than anything read from the environment or the clock.
MEMTARA_SEED = bytes.fromhex(
    "9f2c1d4a7b0e63558ac4d1f0927e3b6a5d81c40fe27a99b3641d0ca7f5382e10"
)
MEMTARA_KID = "memtara-fixture-2026-08"
MEMTARA_ISSUER = "https://attest.memtara.example/v1"

TENANT = "tnt_bank-a"
STREAM = "tnt_bank-a:adr:0"
RECEIPT_KEY_ID = "local://evidence-receipt/dev-1"
ANCHOR_KEY_ID = "local://evidence-anchor/dev-1"
ZERO_HASH = "0" * 64
NON_MANIFEST = ("records.json", "receipts.json", "anchors.json", "checkpoints.json", "keys.json")

# The two proofs the corpus carries, attached to records 0 and 2. `chain_head` is the Memtara
# audit-chain head Mizan observed; section 2.1 is explicit that the token does not sign it, so it
# is committed by the Mizan record hash and by nothing else.
PROOFS = (
    {
        "sequence": 0,
        "jti": "mtr-proof-0f3a1c9d",
        "proof_hash": "3b1f9a0c5d2e47861bb0f4c8a97d2e5613c0a4f89b7e2d6150af38c94e0b7d22",
        "chain_head": "c41d8f0a92b7e35604fa1d8c73e2b09517ae4d3c8016f2b95d7ea340c81b6f29",
    },
    {
        "sequence": 2,
        "jti": "mtr-proof-77b2e410",
        "proof_hash": "a90c4e17f3d825b6041ac7e9d2836150fb4e7c0928d1a35674ecb08f21d94a63",
        "chain_head": "1d7e3c05a9b8f24610cd39b7e05f81a2c46370de92b8104fa5cd7e3b61098d47",
    },
)

# The digest the tampered fixture states in place of the proof it actually holds a token for. It
# is a well-formed lowercase SHA-256 digest, so it passes the phase-4 grammar and is refused only
# where the projection is compared with the signed claim.
FORGED_PROOF_HASH = "deadbeef" * 8


def dev_signing_key(key_id: str) -> Ed25519PrivateKey:
    """The repository's development key derivation: the private half is `sha256(key_id)`.

    These keys are publicly derivable and both verifiers say so, verbatim, on every bundle that
    uses them. That is the correct property for a fixture: the corpus proves the format, and a
    reader who can regenerate the whole bundle can never mistake it for evidence.
    """
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(key_id.encode()).digest())


def public_key_b64(key_id: str) -> str:
    raw = dev_signing_key(key_id).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def sign(key_id: str, payload: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(dev_signing_key(key_id).sign(rfc8785.dumps(payload))).decode()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def memtara_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(MEMTARA_SEED)


def memtara_jwks() -> dict[str, Any]:
    """The operator-supplied RFC 8037 JWK Set: public halves only, and never a bundle member."""
    raw = memtara_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "keys": [
            {
                "alg": "EdDSA",
                "crv": "Ed25519",
                "kid": MEMTARA_KID,
                "kty": "OKP",
                "use": "sig",
                "x": b64url(raw),
            }
        ]
    }


def memtara_token(*, proof_hash: str, jti: str) -> str:
    """A compact EdDSA JWS of the shape section 2.1 requires a retained Memtara token to have.

    `iat`/`exp` are fixed and already in the past. That is deliberate: section 2.1 says historical
    verification does not compare `exp` with the verifier's clock, because expiry governed whether
    Mizan could accept the token at authorization time, while the bundle proves afterwards which
    signed token the immutable ADR used. A fixture whose token is expired and still VALID is the
    only way that sentence stays tested.
    """
    header = {"alg": "EdDSA", "kid": MEMTARA_KID, "typ": "JWT"}
    claims = {
        "aud": "mizan-control-plane",
        "exp": 1786838400,  # 2026-08-15T00:00:00Z + 5 minutes, and long past.
        "iat": 1786838100,
        "iss": MEMTARA_ISSUER,
        "jti": jti,
        "proof_hash": proof_hash,
        "sub": f"urn:memtara:proof:{jti}",
        "verified": True,
    }
    segments = [
        b64url(json.dumps(part, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        for part in (header, claims)
    ]
    signing_input = ".".join(segments).encode("ascii")
    segments.append(b64url(memtara_key().sign(signing_input)))
    return ".".join(segments)


def external_proofs_for(sequence: int, *, forge_binding: bool) -> list[dict[str, str]]:
    """Section 2.1's five members, exactly, or the empty array a 1.3 record with nothing declares.

    When `forge_binding` is set the token is still minted over the *true* `proof_hash` and only
    the projection member is replaced. Signing the forged value instead would move the failure to
    a check every honest verifier passes anyway, and this fixture would stop testing the binding.
    """
    proofs = []
    for proof in PROOFS:
        if proof["sequence"] != sequence:
            continue
        stated = FORGED_PROOF_HASH if forge_binding else proof["proof_hash"]
        proofs.append(
            {
                "issuer": MEMTARA_ISSUER,
                "jti": proof["jti"],
                "memtara_chain_head": proof["chain_head"],
                "proof_hash": stated,
                "token": memtara_token(proof_hash=proof["proof_hash"], jti=proof["jti"]),
            }
        )
    return proofs


def build_records(*, forge_binding: bool) -> list[dict[str, Any]]:
    """Four schema-1.3 records, chained. Records 1 and 3 carry `external_proofs: []` on purpose.

    Section 2.1: an empty array and an absent member are different statements, and a producer that
    dropped the array would otherwise be indistinguishable from one that had nothing to report.
    Two of the four records exercise the empty-array branch that makes that distinction real.
    """
    records: list[dict[str, Any]] = []
    previous = ZERO_HASH
    for sequence in range(4):
        record = {
            "external_proofs": external_proofs_for(sequence, forge_binding=forge_binding),
            "prev_hash": previous,
            "schema_version": "1.3",
            "sequence_number": sequence,
            "stream_id": STREAM,
            "tenant_id": TENANT,
            "value": f"record-{sequence}",
        }
        record["record_hash"] = canonical_hash(record)
        previous = record["record_hash"]
        records.append(record)
    return records


def build_receipts(records: list[dict[str, Any]], object_version: str) -> list[dict[str, Any]]:
    receipts = []
    for record in records:
        payload = {
            "key_id": RECEIPT_KEY_ID,
            "object_key": "segments/tnt_bank-a/export/0-3.json",
            "object_version": object_version,
            "record_hash": record["record_hash"],
            "sequence_number": record["sequence_number"],
            "stream_id": STREAM,
            "tenant_id": TENANT,
        }
        receipts.append({"payload": payload, "signature": sign(RECEIPT_KEY_ID, payload)})
    return receipts


def build_anchors(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = {
        "anchor_id": "018f47a6-7b42-7c00-8000-00000000ba01",
        "anchor_number": 0,
        "anchored_at": "2026-08-25T00:00:00Z",
        "attestations": [
            {
                "authority": "development",
                "evidence": None,
                "obtained_at": None,
                "status": "unattested",
                "type": "none_development",
            }
        ],
        "covered_record_count": len(records),
        "from_sequence": 0,
        "head_hash": records[-1]["record_hash"],
        "key_id": ANCHOR_KEY_ID,
        "object_key": "anchors/tnt_bank-a/export/3.json",
        "object_version": "fixture-version",
        "prev_anchor_hash": ZERO_HASH,
        "stream_id": STREAM,
        "tenant_id": TENANT,
        "to_sequence": records[-1]["sequence_number"],
    }
    return [{"payload": payload, "signature": sign(ANCHOR_KEY_ID, payload)}]


def build_checkpoints(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The unsigned acceleration index. Section 4: it supplies no assurance, and is checked anyway."""
    return [
        {
            "expected_previous": records[0]["prev_hash"],
            "from_sequence": 0,
            "head_hash": records[1]["record_hash"],
            "to_sequence": 1,
        },
        {
            "expected_previous": records[1]["record_hash"],
            "from_sequence": 2,
            "head_hash": records[3]["record_hash"],
            "to_sequence": 3,
        },
    ]


def build_keys() -> list[dict[str, Any]]:
    return [
        {
            "algorithm": "Ed25519",
            "custody": "development-derived",
            "key_id": RECEIPT_KEY_ID,
            "not_after": None,
            "not_before": "2026-08-24T00:00:00Z",
            "public_key": public_key_b64(RECEIPT_KEY_ID),
            "revoked_at": None,
            "role": "evidence-receipt",
        },
        {
            "algorithm": "Ed25519",
            "custody": "development-derived",
            "key_id": ANCHOR_KEY_ID,
            "not_after": None,
            "not_before": "2026-08-24T00:00:00Z",
            "public_key": public_key_b64(ANCHOR_KEY_ID),
            "revoked_at": None,
            "role": "evidence-anchor",
        },
    ]


def build_bundle(directory: Path, *, bundle_version: str, forge_binding: bool = False) -> None:
    records = build_records(forge_binding=forge_binding)
    documents = {
        "records.json": records,
        "receipts.json": build_receipts(records, canonical_hash(records)),
        "anchors.json": build_anchors(records),
        "checkpoints.json": build_checkpoints(records),
        "keys.json": build_keys(),
    }
    directory.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in NON_MANIFEST:
        payload = rfc8785.dumps(documents[name])
        (directory / name).write_bytes(payload)
        files[name] = hashlib.sha256(payload).hexdigest()
    manifest = {
        "assurance": {"anchor_attestation": "unattested", "external_timestamp": False},
        "bundle_version": bundle_version,
        "canonicalization": "RFC8785",
        "files": files,
        "hash_algorithm": "SHA-256",
        "range": {"from_sequence": 0, "to_sequence": records[-1]["sequence_number"]},
        "stream_id": STREAM,
        "tenant_id": TENANT,
    }
    (directory / "manifest.json").write_bytes(rfc8785.dumps(manifest))
    print(f"  {directory}  bundle_version={bundle_version} records={len(records)}")


def main() -> int:
    TRUST_ROOT.write_bytes(rfc8785.dumps(memtara_jwks()) + b"\n")
    print(f"  {TRUST_ROOT}  kid={MEMTARA_KID}")
    build_bundle(CORPUS / "valid-memtara-proof", bundle_version="1.1")
    build_bundle(
        CORPUS / "invalid-memtara-proof-binding", bundle_version="1.1", forge_binding=True
    )
    # Section 2.1's other direction: the member under a manifest that predates it.
    build_bundle(CORPUS / "malformed-memtara-in-1.0", bundle_version="1.0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
