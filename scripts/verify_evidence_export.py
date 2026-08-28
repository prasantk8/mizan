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
import warnings
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID

FILES = ("records.json", "receipts.json", "anchors.json", "checkpoints.json", "keys.json")
ZERO_HASH = "0" * 64
INSTANT = "%Y-%m-%dT%H:%M:%SZ"


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


def der_element(data: bytes, index: int) -> tuple[int, bytes, int]:
    """One DER TLV at `index`: its tag, its contents, and where the next one starts."""
    tag = data[index]
    length = data[index + 1]
    index += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[index:index + count], "big")
        index += count
    return tag, data[index:index + length], index + length


def token_certificates(response: bytes) -> list[x509.Certificate]:
    """The certificates a TimeStampResp carries, or none if it does not parse as one.

    RFC 3161 3.2: TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }.
    The token is a CMS ContentInfo, which is what `cryptography` reads certificates out of. Read
    here rather than by shelling out to `openssl ts -reply -token_out` so that a bundle's declared
    horizon is still legible on a machine with no OpenSSL at all.

    Nothing in here decides whether a token is good — OpenSSL keeps that job, unchanged. An
    unreadable response answers "no certificates", the horizon is then unknown rather than
    breached, and the verdict comes from the same verification it always came from.
    """
    try:
        tag, body, _ = der_element(response, 0)
        if tag != 0x30:
            return []
        _, _, after_status = der_element(body, 0)
        with warnings.catch_warnings():
            # Several public authorities emit BER-encoded SET OF certificates. Reading them is
            # not a trust decision; the chain is still built and still validated below.
            warnings.simplefilter("ignore")
            return list(pkcs7.load_der_pkcs7_certificates(body[after_status:]))
    except Exception:
        return []


def certification_path(
    response: bytes, trust_anchors: list[x509.Certificate] | None = None
) -> list[x509.Certificate]:
    """The certificates a verifier must find valid for this token to verify: signer upwards.

    RFC 3161 2.3 requires the timestamping signer to carry exactly one extended key usage, and for
    it to be `id-kp-timeStamping`. That is what identifies the signer here — not the CMS SignerInfo,
    which would need a full CMS parser to reach and would answer the same question.
    """
    pool = token_certificates(response) + list(trust_anchors or [])
    signer = None
    for candidate in pool:
        try:
            usage = candidate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.TIME_STAMPING in usage:
            signer = candidate
            break
    if signer is None:
        return []
    path = [signer]
    current = signer
    while current.issuer != current.subject:
        issuer = next((item for item in pool if item.subject == current.issuer), None)
        if issuer is None:
            break
        path.append(issuer)
        current = issuer
    return path


def declared_horizon(response: bytes) -> datetime | None:
    """The date this token stops verifying, as the token itself states it.

    The earliest `notAfter` on the certification path the token carries — which is exactly the
    date `openssl ts -verify` starts refusing it, because path validation rejects a chain in
    which any certificate has expired. Trust anchors are excluded on purpose: this is the value
    the control plane writes into the bundle at the moment the token is obtained, when no
    verifier's trust roots are known and none can be assumed.
    """
    path = certification_path(response)
    if not path:
        return None
    return min(certificate.not_valid_after_utc for certificate in path)


def common_validity(
    response: bytes, trust_anchors: list[x509.Certificate]
) -> tuple[datetime, datetime] | None:
    """The window in which every certificate on the path was simultaneously valid, or None."""
    path = certification_path(response, trust_anchors)
    if not path:
        return None
    opened = max(certificate.not_valid_before_utc for certificate in path)
    closes = min(certificate.not_valid_after_utc for certificate in path)
    return None if opened > closes else (opened, closes)


def load_trust_anchors(paths: list[Path]) -> list[x509.Certificate]:
    """Operator trust roots, for horizon arithmetic only.

    A root that does not parse is skipped rather than fatal: OpenSSL is still handed the same
    `-CAfile` and is still the authority on whether the token is trusted. Making an unreadable
    root a CANNOT CHECK would be a better answer than today's "signer is not trusted", but it
    changes a terminal verdict class, and that is a bundle-format decision rather than a
    consequence of stating a horizon.
    """
    anchors: list[x509.Certificate] = []
    for path in paths:
        try:
            anchors.extend(x509.load_pem_x509_certificates(path.read_bytes()))
        except (OSError, ValueError):
            continue
    return anchors


def openssl_timestamp_failure(
    token: Path, digest: str, trust: Path, attime: datetime | None
) -> str | None:
    """`openssl ts -verify`, as of now or as of a stated instant. None means it verified."""
    command = ["openssl", "ts", "-verify", "-in", str(token), "-digest", digest, "-CAfile", str(trust)]
    if attime is not None:
        command[2:2] = ["-attime", str(int(attime.timestamp()))]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
    except (FileNotFoundError, OSError) as exc:
        raise CannotCheck(f"OpenSSL RFC 3161 verification could not be executed: {exc}") from exc
    if completed.returncode == 0:
        return None
    detail = (completed.stderr or completed.stdout).lower()
    if "imprint" in detail or "message digest" in detail:
        return "timestamp message imprint does not match the anchor digest"
    if "expired" in detail:
        return "TSA certificate is expired"
    if "certificate verify" in detail or "unable to get" in detail:
        return "timestamp signer is not trusted by the operator-supplied root"
    return "timestamp token is malformed or its signature is invalid"


def verify_rfc3161(
    attestation: dict[str, Any],
    digest: str,
    trust_anchor_paths: list[Path],
    now: datetime | None = None,
) -> datetime | None:
    """Verify one RFC 3161 attestation and answer with the date it stops verifying.

    None means no certification path could be built from the token and the operator's roots, so the
    horizon is unknown to this verifier; the token was then checked as of now, as it always was.

    Past the horizon the token is re-checked at an instant inside its certification path's own
    common validity window — taken from the certificates, never from the token's `genTime`, which
    would be asking the token to date the certificate that signs it. What that re-check supports is
    narrower than what a live verification supports, and the two are reported as different verdicts
    for that reason: it says the signer chains to the operator's root and the imprint is this
    anchor, not that the anchor existed at the time the token asserts.
    """
    now = now or datetime.now(UTC)
    if not trust_anchor_paths:
        raise VerificationFailure("RFC 3161 attestation requires --tsa-trust-anchor")
    if attestation.get("anchor_digest") != digest or not attestation.get("evidence"):
        raise VerificationFailure("RFC 3161 attestation does not bind the anchor digest")
    anchors = load_trust_anchors(trust_anchor_paths)
    with tempfile.TemporaryDirectory(prefix="mizan-tsa-verify-") as directory:
        token = Path(directory) / "response.tsr"
        trust = Path(directory) / "trust.pem"
        try:
            evidence = base64.b64decode(attestation["evidence"])
            token.write_bytes(evidence)
            trust.write_bytes(b"\n".join(path.read_bytes() for path in trust_anchor_paths))
        except (OSError, ValueError) as exc:
            raise VerificationFailure("RFC 3161 evidence or trust root is malformed") from exc
        stated = declared_horizon(evidence)
        if stated is not None and stated.strftime(INSTANT) != attestation.get("expires_at"):
            raise VerificationFailure(
                "RFC 3161 attestation misstates its own expiry: declared "
                f"{attestation.get('expires_at')}, certificate says {stated.strftime(INSTANT)}"
            )
        try:
            probe = subprocess.run(
                ["openssl", "ts", "-help"], check=False, capture_output=True, text=True
            )
        except (FileNotFoundError, OSError) as exc:
            raise CannotCheck(f"OpenSSL executable is unavailable: {exc}") from exc
        if probe.returncode not in {0, 1} or "-verify" not in (probe.stdout + probe.stderr):
            raise CannotCheck("OpenSSL is installed but RFC 3161 'ts -verify' support is unavailable")
        window = common_validity(evidence, anchors)
        if window is None or window[1] >= now:
            failure = openssl_timestamp_failure(token, digest, trust, None)
            if failure is not None:
                raise VerificationFailure(f"RFC 3161 {failure}")
            return None if window is None else window[1]
        opened, closes = window
        failure = openssl_timestamp_failure(token, digest, trust, opened)
        if failure is not None:
            raise VerificationFailure(f"RFC 3161 {failure}")
        return closes


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
    if "expires_at" in attestation:
        raise MalformedBundle(
            f"anchor {anchor_number} signed payload attestation declares expires_at; the roster "
            "is written before any token exists and cannot know one"
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
    attestation_type = attestation.get("type")
    if attestation_type not in {"rfc3161", "customer_countersignature"}:
        raise MalformedBundle(
            f"anchor {anchor_number} sidecar attestation type "
            f"{attestation_type!r} is illegal"
        )
    expires_at = attestation.get("expires_at")
    if attestation_type == "rfc3161":
        # A bundle that does not state its own horizon leaves a holder to discover it years
        # later, from a failure. Required, so the date arrives with the evidence.
        if not isinstance(expires_at, str):
            raise MalformedBundle(
                f"anchor {anchor_number} RFC 3161 sidecar does not declare expires_at"
            )
        try:
            datetime.strptime(expires_at, INSTANT).replace(tzinfo=UTC)
        except ValueError as exc:
            raise MalformedBundle(
                f"anchor {anchor_number} RFC 3161 sidecar expires_at is not an RFC 3339 UTC "
                f"instant: {expires_at!r}"
            ) from exc
    elif expires_at is not None:
        raise MalformedBundle(
            f"anchor {anchor_number} {attestation_type} sidecar declares expires_at; only an "
            "RFC 3161 attestation has a certificate lifetime to declare"
        )


def verify_bundle(
    bundle: Path,
    tsa_trust_anchors: list[Path] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    tsa_trust_anchors = tsa_trust_anchors or []
    now = now or datetime.now(UTC)
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
            "key_id", "role", "custody", "algorithm", "public_key",
            "not_before", "not_after", "revoked_at",
        }
        if set(item) != required_key_fields:
            raise VerificationFailure(
                f"key {item.get('key_id')} lifecycle metadata is incomplete or contains unknown fields"
            )
        if item.get("algorithm") != "Ed25519":
            raise VerificationFailure(f"key {item.get('key_id')} uses an unsupported algorithm")
        if item.get("custody") not in {"development-derived", "kms", "hsm"}:
            raise MalformedBundle(f"key {item.get('key_id')} has an unsupported custody value")
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
    anchor_assurance: list[tuple[int, str, list[str], str | None]] = []
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
        live_horizons: list[datetime] = []
        passed_horizons: list[datetime] = []
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
                horizon = verify_rfc3161(attestation, digest, tsa_trust_anchors, now)
                if horizon is None or horizon >= now:
                    verified_external = True
                    if horizon is not None:
                        live_horizons.append(horizon)
                else:
                    passed_horizons.append(horizon)
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
            else "expired" if passed_horizons
            else "unattested"
        )
        # One anchor needs one authority to outlive it, so its horizon is the latest of the
        # authorities that carry it, not the earliest. Reporting the earliest would tell a holder
        # that a stream countersigned by two authorities dies with the first of them.
        reached = live_horizons if verified_external else passed_horizons
        anchor_assurance.append((
            number,
            state,
            pending_authorities,
            max(reached).strftime(INSTANT) if reached else None,
        ))
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

    states = [state for _, state, _, _ in anchor_assurance]
    derived_assurance = (
        "rfc3161" if all(state == "rfc3161" for state in states)
        else "expired" if all(state in {"rfc3161", "expired"} for state in states)
        else "unattested" if "unattested" in states
        else "pending"
    )
    # The manifest recorded what was true when the bundle was exported. A horizon that has since
    # passed is a fact about the calendar, not a discrepancy in the bundle, and saying "the claim
    # does not match" would accuse the exporter of the one thing this verdict exists to rule out.
    claim_under_test = "rfc3161" if derived_assurance == "expired" else derived_assurance
    claimed = manifest.get("assurance", {})
    expected_claim = {
        "anchor_attestation": claim_under_test,
        "external_timestamp": claim_under_test == "rfc3161",
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
        "development_custody": any(
            item["custody"] == "development-derived" for item in key_metadata.values()
        ),
        "derived_assurance": derived_assurance,
        "horizon": min(
            (horizon for *_, horizon in anchor_assurance if horizon is not None),
            default=None,
        ),
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
    expired = result["derived_assurance"] == "expired"
    checked = (
        "The exported records, signed receipts, and complete signed anchor chain verified; "
        "unsigned checkpoints were used only as a parallel-verification performance aid "
        f"for sequences {result['from_sequence']} through {result['to_sequence']} "
        f"({result['records']} records, {result['anchors']} anchors)."
    )
    if expired:
        # Everything above this line verified. What ran out is the independent proof of when.
        print(
            f"EXPIRED: {checked} The independent RFC 3161 timestamp coverage stopped being "
            f"verifiable on {result['horizon']}, so this bundle still proves what was recorded "
            "and no longer proves independently when."
        )
    else:
        print(f"PASS: {checked}")
    for anchor_number, assurance, pending_authorities, horizon in result["anchor_assurance"]:
        detail = ""
        if pending_authorities:
            detail = " Pending authorities: " + ", ".join(pending_authorities) + "."
        elif assurance == "expired":
            detail = f" Independent timestamp horizon passed {horizon}."
        elif horizon is not None:
            detail = f" Independently verifiable until {horizon}."
        print(f"ANCHOR {anchor_number} ATTESTATION: {assurance.upper()}.{detail}")
    if result["derived_assurance"] not in {"rfc3161", "expired"}:
        print("ATTESTATION: STREAM NOT EXTERNALLY ANCHORED — at least one anchor lacks a verified RFC 3161 token.")
    for key_id, revoked_at in result["revoked_keys"]:
        print(f"KEY STATUS: valid signature, key {key_id} revoked at {revoked_at}.")
    if result["development_custody"]:
        print(
            "KEY CUSTODY: publicly derivable development key — "
            "this bundle is forgeable by anyone who reads it."
        )
    print(f"ASSURANCE DERIVED: {result['derived_assurance']}.")
    if result["horizon"] is not None:
        tense = "stopped" if expired else "stops"
        print(
            f"TIMESTAMP HORIZON: {result['horizon']} — the date this bundle {tense} being "
            "independently verifiable, read from the timestamp authority's own certificate. "
            "Mizan claims offline verifiability up to that date and no further."
        )
    if result["trust_anchors"]:
        print("TRUST ROOTS USED: " + ", ".join(result["trust_anchors"]))
    print("WHAT THIS CHECKED: File integrity, record ordering/hash links, signed receipt coverage, and signed anchor continuity.")
    if expired:
        print(
            "LIMITATION: Past the horizon the timestamp token was re-checked at an instant inside "
            "its own certificate's validity window, which shows the signer chains to your trust "
            "root and the imprint is this anchor. It does not show the anchor existed at the time "
            "the token asserts: dating a certificate by the token it signed proves nothing."
        )
    if result["derived_assurance"] not in {"rfc3161", "expired"}:
        print("LIMITATION: The anchor signature is Mizan's own. No complete independent timestamp coverage is present, so a party holding Mizan's database and signing key could rebuild and re-sign this history.")
    print("NOT COVERED: Records omitted before chaining and an entire final anchor withheld before export leave no proof in this bundle.")
    return 4 if expired else 0


if __name__ == "__main__":
    raise SystemExit(main())
