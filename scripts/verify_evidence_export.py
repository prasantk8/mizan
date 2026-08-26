#!/usr/bin/env python3
# Install: python -m pip install rfc8785==0.1.4 cryptography==50.0.0
"""Standalone Mizan evidence verifier: no control-plane, database, or network dependency."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FILES = ("records.json", "receipts.json", "anchors.json", "checkpoints.json", "keys.json")
ZERO_HASH = "0" * 64


class VerificationFailure(ValueError):
    pass


class MalformedBundle(VerificationFailure):
    """The input does not conform to the Mizan bundle 1.0 grammar."""


class CannotCheck(RuntimeError):
    """The verifier environment cannot evaluate a claim; evidence is not condemned."""


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedBundle(f"{path.name} is missing or malformed: {exc}") from exc


def verify_signature(payload: dict[str, Any], signature: str, key: Ed25519PublicKey, label: str) -> None:
    try:
        key.verify(base64.urlsafe_b64decode(signature), rfc8785.dumps(payload))
    except Exception as exc:
        raise VerificationFailure(f"{label} signature is invalid") from exc


def verify_rfc3161(
    attestation: dict[str, Any], digest: str, trust_anchors: list[Path]
) -> None:
    if not trust_anchors:
        raise VerificationFailure("RFC 3161 attestation requires --tsa-trust-anchor")
    if attestation.get("anchor_digest") != digest or not attestation.get("evidence"):
        raise VerificationFailure("RFC 3161 attestation does not bind the anchor digest")
    with tempfile.TemporaryDirectory(prefix="mizan-tsa-verify-") as directory:
        token = Path(directory) / "response.tsr"
        trust = Path(directory) / "trust.pem"
        try:
            token.write_bytes(base64.b64decode(attestation["evidence"]))
            trust.write_bytes(b"\n".join(path.read_bytes() for path in trust_anchors))
        except (OSError, ValueError) as exc:
            raise VerificationFailure("RFC 3161 evidence or trust root is malformed") from exc
        try:
            probe = subprocess.run(
                ["openssl", "ts", "-help"], check=False, capture_output=True, text=True
            )
        except (FileNotFoundError, OSError) as exc:
            raise CannotCheck(f"OpenSSL executable is unavailable: {exc}") from exc
        if probe.returncode not in {0, 1} or "-verify" not in (probe.stdout + probe.stderr):
            raise CannotCheck("OpenSSL is installed but RFC 3161 'ts -verify' support is unavailable")
        try:
            completed = subprocess.run(
                ["openssl", "ts", "-verify", "-in", str(token), "-digest", digest, "-CAfile", str(trust)],
                check=False,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, OSError) as exc:
            raise CannotCheck(f"OpenSSL RFC 3161 verification could not be executed: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).lower()
            if "expired" in detail:
                reason = "TSA certificate is expired"
            elif "imprint" in detail or "message digest" in detail:
                reason = "timestamp message imprint does not match the anchor digest"
            elif "certificate verify" in detail or "unable to get" in detail:
                reason = "timestamp signer is not trusted by the operator-supplied root"
            else:
                reason = "timestamp token is malformed or its signature is invalid"
            raise VerificationFailure(f"RFC 3161 {reason}")


def validate_signed_attestation(attestation: Any, anchor_number: int) -> None:
    if not isinstance(attestation, dict):
        raise MalformedBundle(
            f"anchor {anchor_number} signed payload attestation is not an object"
        )
    attestation_type = attestation.get("type")
    status = attestation.get("status")
    if status == "failed":
        raise MalformedBundle(
            f"anchor {anchor_number} signed payload attestation status 'failed' "
            "is reserved in bundle 1.0"
        )
    if attestation_type == "none_development":
        if status != "unattested" or attestation.get("authority") != "development":
            raise MalformedBundle(
                f"anchor {anchor_number} signed payload none_development attestation "
                "must be unattested with authority 'development'"
            )
        return
    if attestation_type in {"rfc3161", "customer_countersignature"}:
        if status != "pending":
            raise MalformedBundle(
                f"anchor {anchor_number} signed payload attestation status {status!r} "
                f"is illegal for type {attestation_type!r}"
            )
        return
    raise MalformedBundle(
        f"anchor {anchor_number} signed payload attestation type {attestation_type!r} is unknown"
    )


def validate_sidecar_attestation(attestation: Any, anchor_number: int) -> None:
    if not isinstance(attestation, dict):
        raise MalformedBundle(f"anchor {anchor_number} attestation sidecar is not an object")
    status = attestation.get("status")
    if status == "failed":
        raise MalformedBundle(
            f"anchor {anchor_number} sidecar attestation status 'failed' "
            "is reserved in bundle 1.0"
        )
    if status != "attested":
        raise MalformedBundle(
            f"anchor {anchor_number} sidecar attestation status {status!r} is illegal"
        )
    if attestation.get("type") not in {"rfc3161", "customer_countersignature"}:
        raise MalformedBundle(
            f"anchor {anchor_number} sidecar attestation type "
            f"{attestation.get('type')!r} is illegal"
        )


def verify_bundle(bundle: Path, tsa_trust_anchors: list[Path] | None = None) -> dict[str, Any]:
    tsa_trust_anchors = tsa_trust_anchors or []
    manifest = load_json(bundle / "manifest.json")
    if manifest.get("bundle_version") != "1.0":
        raise MalformedBundle("manifest bundle_version is unsupported")
    if manifest.get("canonicalization") != "RFC8785":
        raise MalformedBundle("manifest canonicalization is unsupported")
    if manifest.get("hash_algorithm") != "SHA-256":
        raise MalformedBundle("manifest hash_algorithm is unsupported")
    if set(manifest.get("files", {})) != set(FILES):
        raise MalformedBundle("manifest file inventory is incomplete or contains unknown files")
    records = load_json(bundle / "records.json")
    receipts = load_json(bundle / "receipts.json")
    anchors = load_json(bundle / "anchors.json")
    checkpoints = load_json(bundle / "checkpoints.json")
    key_documents = load_json(bundle / "keys.json")
    for name in FILES:
        path = bundle / name
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise VerificationFailure(f"{name} is missing") from exc
        if actual != manifest["files"][name]:
            raise VerificationFailure(f"{name} checksum mismatch")

    if not records:
        raise VerificationFailure("record set is empty")
    keys: dict[str, Ed25519PublicKey] = {}
    key_metadata: dict[str, dict[str, Any]] = {}
    for item in key_documents:
        required_key_fields = {
            "key_id", "role", "algorithm", "public_key", "not_before", "not_after", "revoked_at"
        }
        if set(item) != required_key_fields:
            raise VerificationFailure(
                f"key {item.get('key_id')} lifecycle metadata is incomplete or contains unknown fields"
            )
        if item.get("algorithm") != "Ed25519":
            raise VerificationFailure(f"key {item.get('key_id')} uses an unsupported algorithm")
        try:
            keys[item["key_id"]] = Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(item["public_key"])
            )
            key_metadata[item["key_id"]] = item
        except Exception as exc:
            raise VerificationFailure(f"key {item.get('key_id')} is malformed") from exc

    range_start = manifest["range"]["from_sequence"]
    range_end = manifest["range"]["to_sequence"]
    previous = ZERO_HASH if range_start == 0 else records[0].get("prev_hash")
    for offset, record in enumerate(records):
        sequence = range_start + offset
        if record.get("sequence_number") != sequence:
            raise VerificationFailure(
                f"record order mismatch: expected sequence {sequence}, got {record.get('sequence_number')}"
            )
        if record.get("prev_hash") != previous:
            raise VerificationFailure(f"record chain previous-hash mismatch at sequence {sequence}")
        actual_hash = canonical_hash({key: value for key, value in record.items() if key != "record_hash"})
        if actual_hash != record.get("record_hash"):
            raise VerificationFailure(f"record hash mismatch at sequence {sequence}")
        previous = record["record_hash"]
    if records[-1]["sequence_number"] != range_end:
        raise VerificationFailure("record range does not reach the manifest terminal sequence")

    receipt_by_sequence: dict[int, dict[str, Any]] = {}
    for receipt in receipts:
        payload = receipt.get("payload", {})
        sequence = payload.get("sequence_number")
        if sequence in receipt_by_sequence:
            raise VerificationFailure(f"duplicate receipt at sequence {sequence}")
        key = keys.get(payload.get("key_id"))
        if key is None:
            raise VerificationFailure(f"receipt key is unavailable at sequence {sequence}")
        if key_metadata[payload["key_id"]].get("role") != "evidence-receipt":
            raise VerificationFailure(f"receipt key has wrong role at sequence {sequence}")
        verify_signature(payload, receipt.get("signature", ""), key, f"receipt {sequence}")
        receipt_by_sequence[sequence] = payload
    for record in records:
        sequence = record["sequence_number"]
        receipt = receipt_by_sequence.get(sequence)
        if receipt is None:
            raise VerificationFailure(f"receipt coverage missing at sequence {sequence}")
        if (
            receipt.get("tenant_id") != manifest["tenant_id"]
            or receipt.get("stream_id") != manifest["stream_id"]
            or receipt.get("record_hash") != record["record_hash"]
        ):
            raise VerificationFailure(f"receipt binding mismatch at sequence {sequence}")

    expected_anchor_previous = ZERO_HASH
    expected_anchor_from = 0
    if not anchors:
        raise VerificationFailure("anchor set is empty")
    anchor_assurance: list[tuple[int, str]] = []
    for expected_anchor_number, row in enumerate(anchors):
        payload = row.get("payload", {})
        number = payload.get("anchor_number")
        if number != expected_anchor_number:
            raise VerificationFailure(
                f"anchor number gap: expected {expected_anchor_number}, got {number}"
            )
        if payload.get("prev_anchor_hash") != expected_anchor_previous:
            raise VerificationFailure(f"anchor previous-hash mismatch at anchor {number}")
        if payload.get("from_sequence") != expected_anchor_from:
            raise VerificationFailure(f"anchor range gap at anchor {number}")
        declared = payload.get("covered_record_count")
        if declared != payload.get("to_sequence") - payload.get("from_sequence") + 1:
            raise VerificationFailure(f"anchor covered-record count is inconsistent at anchor {number}")
        declared_attestations = payload.get("attestations")
        if not isinstance(declared_attestations, list) or not declared_attestations:
            raise MalformedBundle(f"anchor {number} signed attestation roster is missing")
        for item in declared_attestations:
            validate_signed_attestation(item, number)
        key = keys.get(payload.get("key_id"))
        if key is None:
            raise VerificationFailure(f"anchor key is unavailable at anchor {number}")
        if key_metadata[payload["key_id"]].get("role") != "evidence-anchor":
            raise VerificationFailure(f"anchor key has wrong role at anchor {number}")
        verify_signature(payload, row.get("signature", ""), key, f"anchor {number}")
        # Final attestations are append-only sidecars. The signed payload retains the
        # original pending marker so completing asynchronous work never rewrites history.
        declared_by_authority = {
            (item.get("type"), item.get("authority")): item
            for item in declared_attestations
        }
        if len(declared_by_authority) != len(declared_attestations):
            raise MalformedBundle(
                f"anchor {number} signed attestation roster contains duplicate authorities"
            )
        effective_attestations = dict(declared_by_authority)
        sidecars = row.get("attestations", [])
        if not isinstance(sidecars, list):
            raise MalformedBundle(f"anchor {number} attestation sidecars are malformed")
        for sidecar in sidecars:
            validate_sidecar_attestation(sidecar, number)
            identity = (sidecar.get("type"), sidecar.get("authority"))
            if identity not in declared_by_authority:
                raise VerificationFailure(
                    f"anchor {number} sidecar authority is absent from the signed roster: "
                    f"{identity[1]}"
                )
            effective_attestations[identity] = sidecar
        verified_external = False
        pending = False
        pending_authorities: list[str] = []
        explicitly_unattested = False
        for attestation in effective_attestations.values():
            if attestation.get("type") == "none_development":
                if attestation.get("status") != "unattested":
                    raise VerificationFailure(
                        f"anchor {number} development attestation is not labelled unattested"
                    )
                explicitly_unattested = True
            elif attestation.get("status") != "attested":
                if attestation.get("status") == "pending":
                    pending = True
                    pending_authorities.append(str(attestation.get("authority")))
                    continue
                raise VerificationFailure(f"anchor {number} has no verified external attestation")
            elif attestation.get("type") == "rfc3161":
                core = {
                    key: value for key, value in payload.items()
                    if key not in {"attestations", "object_key", "object_version"}
                }
                digest = hashlib.sha256(rfc8785.dumps(core)).hexdigest()
                verify_rfc3161(attestation, digest, tsa_trust_anchors)
                verified_external = True
            elif attestation.get("type") == "customer_countersignature":
                key = keys.get(attestation.get("key_id"))
                if key is None:
                    raise VerificationFailure("customer countersignature key is unavailable")
                core = {
                    key_name: value for key_name, value in payload.items()
                    if key_name not in {"attestations", "object_key", "object_version"}
                }
                digest = hashlib.sha256(rfc8785.dumps(core)).digest()
                if attestation.get("anchor_digest") != digest.hex():
                    raise VerificationFailure("customer countersignature digest mismatch")
                try:
                    key.verify(base64.urlsafe_b64decode(attestation["evidence"]), digest)
                except Exception as exc:
                    raise VerificationFailure("customer countersignature is invalid") from exc
        state = (
            "unattested" if explicitly_unattested
            else "pending" if pending
            else "rfc3161" if verified_external
            else "unattested"
        )
        anchor_assurance.append((number, state, pending_authorities))
        expected_anchor_from = payload["to_sequence"] + 1
        expected_anchor_previous = canonical_hash(payload)
    if anchors[-1]["payload"]["to_sequence"] != range_end:
        raise VerificationFailure(
            f"stale terminal anchor: ends at {anchors[-1]['payload']['to_sequence']}, records end at {range_end}"
        )
    if anchors[-1]["payload"].get("head_hash") != records[-1]["record_hash"]:
        raise VerificationFailure("terminal anchor head does not match the terminal record")
    records_by_sequence = {record["sequence_number"]: record for record in records}
    preceding_anchor = None
    for row in anchors:
        payload = row["payload"]
        terminal = payload["to_sequence"]
        if terminal == range_start - 1:
            preceding_anchor = payload
        record = records_by_sequence.get(terminal)
        if record is not None and payload.get("head_hash") != record["record_hash"]:
            raise VerificationFailure(
                f"anchor {payload['anchor_number']} head does not match record {terminal}"
            )
    if range_start > 0:
        if preceding_anchor is None:
            raise VerificationFailure("left-edge anchor is missing")
        if preceding_anchor.get("head_hash") != records[0]["prev_hash"]:
            raise VerificationFailure(
                f"left-edge anchor head does not match record {range_start} previous hash"
            )

    expected_checkpoint_from = range_start
    for index, checkpoint in enumerate(checkpoints):
        if checkpoint.get("from_sequence") != expected_checkpoint_from:
            raise VerificationFailure(f"checkpoint range gap at checkpoint {index}")
        selected = [
            record for record in records
            if checkpoint["from_sequence"] <= record["sequence_number"] <= checkpoint["to_sequence"]
        ]
        if not selected or selected[0]["prev_hash"] != checkpoint.get("expected_previous"):
            raise VerificationFailure(f"checkpoint previous-hash mismatch at checkpoint {index}")
        if selected[-1]["record_hash"] != checkpoint.get("head_hash"):
            raise VerificationFailure(f"checkpoint head mismatch at checkpoint {index}")
        expected_checkpoint_from = checkpoint["to_sequence"] + 1
    if expected_checkpoint_from != range_end + 1:
        raise VerificationFailure("checkpoint coverage does not reach the terminal record")

    states = [state for _, state, _ in anchor_assurance]
    derived_assurance = (
        "rfc3161" if all(state == "rfc3161" for state in states)
        else "unattested" if "unattested" in states
        else "pending"
    )
    claimed = manifest.get("assurance", {})
    expected_claim = {
        "anchor_attestation": derived_assurance,
        "external_timestamp": derived_assurance == "rfc3161",
    }
    if claimed != expected_claim:
        raise VerificationFailure("manifest assurance claim does not match verified attestations")

    return {
        "records": len(records),
        "from_sequence": range_start,
        "to_sequence": range_end,
        "anchors": len(anchors),
        "anchor_attestation": manifest["assurance"]["anchor_attestation"],
        "anchor_assurance": anchor_assurance,
        "revoked_keys": sorted({
            item["key_id"]: item["revoked_at"]
            for item in key_metadata.values()
            if item.get("revoked_at")
        }.items()),
        "derived_assurance": derived_assurance,
        "trust_anchors": [str(path) for path in tsa_trust_anchors],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a self-contained Mizan evidence bundle")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--tsa-trust-anchor", action="append", type=Path, default=[])
    args = parser.parse_args()
    try:
        result = verify_bundle(args.bundle, args.tsa_trust_anchor)
    except CannotCheck as exc:
        print(f"CANNOT CHECK: {exc}", file=sys.stderr)
        print(
            "ASSURANCE NOT DERIVED: RFC 3161 evidence was not evaluated; "
            "this is weaker than a successful verification.",
            file=sys.stderr,
        )
        return 2
    except MalformedBundle as exc:
        print(f"MALFORMED: {exc}", file=sys.stderr)
        return 3
    except VerificationFailure as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "PASS: The exported records, signed receipts, and complete signed anchor chain verified; "
        "unsigned checkpoints were used only as a parallel-verification performance aid "
        f"for sequences {result['from_sequence']} through {result['to_sequence']} "
        f"({result['records']} records, {result['anchors']} anchors)."
    )
    for anchor_number, assurance, pending_authorities in result["anchor_assurance"]:
        suffix = (
            " Pending authorities: " + ", ".join(pending_authorities) + "."
            if pending_authorities else ""
        )
        print(f"ANCHOR {anchor_number} ATTESTATION: {assurance.upper()}.{suffix}")
    if result["derived_assurance"] != "rfc3161":
        print("ATTESTATION: STREAM NOT EXTERNALLY ANCHORED — at least one anchor lacks a verified RFC 3161 token.")
    for key_id, revoked_at in result["revoked_keys"]:
        print(f"KEY STATUS: valid signature, key {key_id} revoked at {revoked_at}.")
    print(f"ASSURANCE DERIVED: {result['derived_assurance']}.")
    if result["trust_anchors"]:
        print("TRUST ROOTS USED: " + ", ".join(result["trust_anchors"]))
    print("WHAT THIS CHECKED: File integrity, record ordering/hash links, signed receipt coverage, and signed anchor continuity.")
    if result["derived_assurance"] != "rfc3161":
        print("LIMITATION: The anchor signature is Mizan's own. No complete independent timestamp coverage is present, so a party holding Mizan's database and signing key could rebuild and re-sign this history.")
    print("NOT COVERED: Records omitted before chaining and an entire final anchor withheld before export leave no proof in this bundle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
