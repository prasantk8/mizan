from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .evidence import ChainCheckpoint, EvidenceRepository, LocalImmutableObjectStore

BUNDLE_FILES = ("records.json", "receipts.json", "anchors.json", "checkpoints.json", "keys.json")


def load_public_keyset(path: Path) -> tuple[dict[str, Ed25519PublicKey], list[dict[str, Any]]]:
    """Load the public verification-key document published by Mizan."""
    documents = json.loads(path.read_bytes())
    if not isinstance(documents, list) or not documents:
        raise ValueError("verification keyset must be a non-empty JSON array")
    keys: dict[str, Ed25519PublicKey] = {}
    for document in documents:
        if document.get("algorithm") != "Ed25519":
            raise ValueError(f"unsupported key algorithm for {document.get('key_id')}")
        key_id = document.get("key_id")
        if not isinstance(key_id, str) or key_id in keys:
            raise ValueError("verification key IDs must be unique strings")
        keys[key_id] = Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(document["public_key"])
        )
    return keys, documents


# A key whose private half is `sha256(key_id)` and whose `key_id` ships inside every bundle. A
# holder of such a bundle can forge an indistinguishable one, so it is not evidence of anything.
DEVELOPMENT_CUSTODY = "development-derived"


class DevelopmentCustodyRefused(Exception):
    """Export refused because the signing keys are publicly derivable.

    T-053 made custody *honest* -- the keyset says `development-derived` and the verifier prints
    a warning above the verdict. But a warning is advice, and the exporter never read the field
    at all: `evidence_export.py` contained no mention of custody before T-065. So a bundle that
    anyone could forge was produced, written to disk and handed over, with nothing but prose
    between it and an auditor.

    This is the difference between "no bundle leaves the building" as a process rule and as a
    property of the system. The override exists because development bundles are genuinely needed
    -- `make demo` produces one, and the conformance corpus is made of them -- but it has to be
    asked for by name, and the bundle then carries the fact that it was.
    """


def development_custody_key_ids(key_documents: list[dict[str, Any]]) -> list[str]:
    """Key IDs in this keyset whose private half is publicly derivable."""
    return sorted(
        document["key_id"]
        for document in key_documents
        if document.get("custody") == DEVELOPMENT_CUSTODY
    )


def _write(path: Path, value: Any) -> str:
    payload = rfc8785.dumps(value)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def export_evidence_bundle(
    repository: Any,
    store: LocalImmutableObjectStore,
    public_keys: dict[str, Ed25519PublicKey],
    tenant_id: str,
    stream_id: str,
    target: Path,
    start: int | None = None,
    end: int | None = None,
    checkpoint_interval: int = 1000,
    key_documents: list[dict[str, Any]] | None = None,
    development_custody_reason: str | None = None,
) -> Path:
    """Export authoritative object evidence; Postgres record documents are not trusted.

    Refuses outright when any signing key is `development-derived`, unless
    `development_custody_reason` names why -- in which case the reason is written into the
    manifest, so the bundle itself carries the fact that someone decided to export it anyway.
    """
    development_keys = development_custody_key_ids(key_documents or [])
    if development_keys and development_custody_reason is None:
        raise DevelopmentCustodyRefused(
            "signing keys "
            + ", ".join(development_keys)
            + " are development-derived: their private halves are sha256(key_id) and the key_id "
            "ships inside this bundle, so anyone who reads it can forge an indistinguishable "
            "one. Pass --allow-development-custody with a reason to export anyway; the reason "
            "is recorded in the manifest and reported by the verifier."
        )

    target.mkdir(parents=True, exist_ok=False)
    receipts = repository.receipt_rows(tenant_id, stream_id, start, end)
    records_by_sequence: dict[int, dict[str, Any]] = {}
    for receipt in receipts:
        payload = receipt["payload"]
        raw = store.get(payload["object_key"])
        stored = json.loads(raw)
        candidates = stored if isinstance(stored, list) else [stored]
        matches = [
            record for record in candidates
            if record["sequence_number"] == payload["sequence_number"]
            and record["record_hash"] == payload["record_hash"]
        ]
        if len(matches) != 1 or payload["sequence_number"] in records_by_sequence:
            raise ValueError(f"receipt/object mismatch at sequence {payload['sequence_number']}")
        records_by_sequence[payload["sequence_number"]] = matches[0]
    records = [records_by_sequence[index] for index in sorted(records_by_sequence)]
    if not records:
        raise ValueError("cannot export an empty evidence range")
    range_start = records[0]["sequence_number"]
    range_end = records[-1]["sequence_number"]
    checkpoints = []
    for offset in range(0, len(records), checkpoint_interval):
        group = records[offset : offset + checkpoint_interval]
        checkpoint = ChainCheckpoint(
            group[0]["sequence_number"],
            group[-1]["sequence_number"],
            group[0]["prev_hash"],
            group[-1]["record_hash"],
        )
        checkpoints.append(
            {
                "from_sequence": checkpoint.from_sequence,
                "to_sequence": checkpoint.to_sequence,
                "expected_previous": checkpoint.expected_previous,
                "head_hash": checkpoint.head_hash,
            }
        )
    keys = key_documents or [
        {
            "key_id": key_id,
            "algorithm": "Ed25519",
            "public_key": base64.urlsafe_b64encode(
                key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            ).decode(),
        }
        for key_id, key in sorted(public_keys.items())
    ]
    anchors = repository.anchors(tenant_id, stream_id)
    effective_attestations = []
    for row in anchors:
        declared = row.get("payload", {}).get("attestations", [])
        declared_by_authority = {
            (item.get("type"), item.get("authority")): item for item in declared
        }
        if len(declared_by_authority) != len(declared):
            raise ValueError("anchor signed attestation roster contains duplicate authorities")
        effective = dict(declared_by_authority)
        for sidecar in row.get("attestations", []):
            identity = (sidecar.get("type"), sidecar.get("authority"))
            if identity not in declared_by_authority:
                raise ValueError(
                    "anchor attestation sidecar names an authority absent from the signed roster"
                )
            effective[identity] = sidecar
        effective_attestations.append(list(effective.values()))
    anchor_assurance = [
        "pending"
        if any(item.get("status") == "pending" for item in items)
        else "rfc3161"
        if any(item.get("type") == "rfc3161" and item.get("status") == "attested" for item in items)
        else "unattested"
        for items in effective_attestations
    ]
    externally_attested = bool(anchors) and all(state == "rfc3161" for state in anchor_assurance)
    assurance = (
        "rfc3161" if externally_attested
        else "unattested" if "unattested" in anchor_assurance
        else "pending"
    )
    documents = {
        "records.json": records,
        "receipts.json": receipts,
        "anchors.json": anchors,
        "checkpoints.json": checkpoints,
        "keys.json": keys,
    }
    file_hashes = {name: _write(target / name, value) for name, value in documents.items()}
    # Adaptive, the way every format bump here has been: a bundle declares the lowest version
    # that can describe what it actually contains. `external_proofs` exists only in bundle 1.1,
    # and both offline verifiers refuse a record carrying it under a 1.0 manifest -- so a bundle
    # with proofs must say 1.1. A bundle without them says 1.0 and stays verifiable by a
    # verifier that only ever learned 1.0, which is the whole point of not bumping uniformly.
    bundle_version = "1.1" if any("external_proofs" in record for record in records) else "1.0"
    manifest = {
        "bundle_version": bundle_version,
        "canonicalization": "RFC8785",
        "hash_algorithm": "SHA-256",
        "tenant_id": tenant_id,
        "stream_id": stream_id,
        "range": {"from_sequence": range_start, "to_sequence": range_end},
        "files": file_hashes,
        "assurance": {
            "anchor_attestation": assurance,
            "external_timestamp": externally_attested,
        },
    }
    if development_keys:
        # Additive and optional: a bundle without this field is unchanged, and its absence means
        # what it always meant. Present, it is the record that a refusal was overridden -- which
        # a holder should see without having to know to ask.
        manifest["custody_override"] = {
            "custody": DEVELOPMENT_CUSTODY,
            "key_ids": development_keys,
            "reason": development_custody_reason,
        }
    _write(target / "manifest.json", manifest)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a self-contained Mizan evidence bundle")
    parser.add_argument("--database-url", required=True, help="PostgreSQL runtime-role DSN")
    parser.add_argument("--object-store", required=True, type=Path, help="Immutable object-store root")
    parser.add_argument("--keyset", required=True, type=Path, help="Published verification keyset JSON")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--stream-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--from-sequence", type=int)
    parser.add_argument("--to-sequence", type=int)
    parser.add_argument("--checkpoint-interval", type=int, default=1000)
    parser.add_argument(
        "--allow-development-custody",
        metavar="REASON",
        help="export even though the signing keys are publicly derivable, and record this reason "
        "in the manifest. Required for any bundle signed with development custody -- the demo and "
        "the conformance corpus both need it. A bundle exported this way is not evidence: anyone "
        "who reads it can forge an indistinguishable one.",
    )
    args = parser.parse_args(argv)
    if args.allow_development_custody is not None and not args.allow_development_custody.strip():
        parser.error("--allow-development-custody requires a reason, not an empty string")
    if args.checkpoint_interval < 1:
        parser.error("--checkpoint-interval must be positive")
    repository = EvidenceRepository(args.database_url)
    try:
        public_keys, key_documents = load_public_keyset(args.keyset)
        target = export_evidence_bundle(
            repository,
            LocalImmutableObjectStore(args.object_store),
            public_keys,
            args.tenant_id,
            args.stream_id,
            args.output,
            start=args.from_sequence,
            end=args.to_sequence,
            checkpoint_interval=args.checkpoint_interval,
            key_documents=key_documents,
            development_custody_reason=args.allow_development_custody,
        )
    except DevelopmentCustodyRefused as refusal:
        print(f"EXPORT REFUSED: {refusal}", file=sys.stderr)
        return 3
    finally:
        repository.pool.close()
    if args.allow_development_custody:
        # Loud on the way out, because the operator who typed the flag is not the person who
        # will be holding the bundle a week later.
        print(
            f"WARNING: exported under development custody by explicit override "
            f"({args.allow_development_custody}). This bundle is forgeable by anyone who reads "
            f"it and is not evidence.",
            file=sys.stderr,
        )
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
