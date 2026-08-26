from __future__ import annotations

import base64
import hashlib
import subprocess
import tempfile
import urllib.request
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785


class Rfc3161AnchorProvider:
    """Asynchronous RFC 3161 provider: anchor writes pending, worker obtains tokens later."""

    def __init__(
        self,
        endpoints: list[str],
        trust_anchors: list[Path] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not endpoints:
            raise ValueError("at least one RFC 3161 endpoint is required")
        self.endpoints = endpoints
        self.trust_anchors = trust_anchors or []
        self.timeout_seconds = timeout_seconds

    def attest(self, anchor_payload: dict[str, Any]) -> list[dict[str, Any]]:
        digest = hashlib.sha256(rfc8785.dumps(anchor_payload)).hexdigest()
        requested_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        return [
            {
                "type": "rfc3161",
                "status": "pending",
                "authority": endpoint,
                "obtained_at": None,
                "requested_at": requested_at,
                "anchor_digest": digest,
                "evidence": None,
            }
            for endpoint in self.endpoints
        ]

    def obtain(self, pending: dict[str, Any]) -> dict[str, Any]:
        digest = pending["anchor_digest"]
        with tempfile.TemporaryDirectory(prefix="mizan-tsa-query-") as directory:
            query = Path(directory) / "request.tsq"
            completed = subprocess.run(
                ["openssl", "ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", str(query)],
                check=False,
                capture_output=True,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"RFC 3161 query construction failed: {completed.stderr.decode()}")
            request = urllib.request.Request(
                pending["authority"],
                data=query.read_bytes(),
                headers={"Content-Type": "application/timestamp-query"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                token = response.read()
            failure_reason = self._validation_failure(token, digest, Path(directory))
        if failure_reason is not None:
            return pending | {
                "status": "pending",
                "obtained_at": None,
                "evidence": None,
                "failure_reason": failure_reason,
            }
        return pending | {
            "status": "attested",
            "obtained_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "evidence": base64.b64encode(token).decode(),
        }

    def _validation_failure(self, token: bytes, digest: str, directory: Path) -> str | None:
        if not self.trust_anchors:
            return "token validation unavailable: no TSA trust anchor configured"
        response = directory / "response.tsr"
        trust = directory / "trust.pem"
        try:
            response.write_bytes(token)
            trust.write_bytes(b"\n".join(path.read_bytes() for path in self.trust_anchors))
        except OSError as exc:
            return f"token validation input unavailable: {exc}"
        completed = subprocess.run(
            [
                "openssl", "ts", "-verify", "-in", str(response),
                "-digest", digest, "-CAfile", str(trust),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            reason = completed.stderr.strip() or "OpenSSL rejected the timestamp response"
            return f"RFC 3161 token validation failed: {reason}"
        return None

    def attestation_validation_failure(
        self,
        attestation: dict[str, Any],
        expected_digest: str,
        expected_authority: str,
    ) -> str | None:
        if attestation.get("type") != "rfc3161":
            return "stored attestation type does not match the RFC 3161 slot"
        if attestation.get("authority") != expected_authority:
            return "stored attestation authority does not match its immutable slot"
        if attestation.get("status") != "attested":
            return "stored attestation is not a validated outcome"
        if attestation.get("anchor_digest") != expected_digest:
            return "stored attestation commits to a different anchor digest"
        try:
            token = base64.b64decode(attestation.get("evidence", ""), validate=True)
        except (TypeError, ValueError):
            return "stored RFC 3161 evidence is malformed"
        if not token:
            return "stored RFC 3161 evidence is missing"
        with tempfile.TemporaryDirectory(prefix="mizan-tsa-recheck-") as directory:
            return self._validation_failure(token, expected_digest, Path(directory))


def pending_attestation_breaker_open(
    attestations: list[dict[str, Any]], max_pending_seconds: int, now: datetime | None = None
) -> bool:
    now = now or datetime.now(UTC)
    for item in attestations:
        if item.get("status") != "pending":
            continue
        requested = datetime.fromisoformat(item["requested_at"].replace("Z", "+00:00"))
        if (now - requested).total_seconds() > max_pending_seconds:
            return True
    return False


def customer_countersignature(
    anchor_payload: dict[str, Any], authority: str, signing_key: Any
) -> dict[str, Any]:
    digest = hashlib.sha256(rfc8785.dumps(anchor_payload)).digest()
    return {
        "type": "customer_countersignature",
        "status": "attested",
        "authority": authority,
        "obtained_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "anchor_digest": digest.hex(),
        "key_id": signing_key.key_id,
        "evidence": base64.urlsafe_b64encode(signing_key.sign(digest)).decode(),
    }


class CustomerCountersignatureProvider:
    """Additive customer-KMS attestation; it never satisfies the RFC 3161 floor."""

    def __init__(self, authority: str, signing_key: Any) -> None:
        self.authority = authority
        self.signing_key = signing_key

    def attest(self, anchor_payload: dict[str, Any]) -> dict[str, Any]:
        return customer_countersignature(anchor_payload, self.authority, self.signing_key)


class AnchorAttestationWorker:
    def __init__(self, repository: Any, provider: Rfc3161AnchorProvider, breaker: Any) -> None:
        self.repository = repository
        self.provider = provider
        self.breaker = breaker

    def process(
        self,
        tenant_id: str,
        anchor_rows: list[dict[str, Any]],
        max_pending_seconds: int,
        now: datetime | None = None,
    ) -> int:
        completed = 0
        for row in anchor_rows:
            payload = row["payload"]
            lease_factory = getattr(self.repository, "lease_anchor_attestation", None)
            lease = (
                lease_factory(tenant_id, payload["anchor_id"])
                if lease_factory is not None
                else nullcontext(row.get("attestations", []))
            )
            with lease as leased_attestations:
                if leased_attestations is None:
                    continue
                occupied = {
                    (item.get("type"), item.get("authority")): item
                    for item in leased_attestations
                }
                core = {
                    key: value
                    for key, value in payload.items()
                    if key not in {"attestations", "object_key", "object_version"}
                }
                expected_digest = hashlib.sha256(rfc8785.dumps(core)).hexdigest()
                for pending in payload.get("attestations", []):
                    if pending.get("type") != "rfc3161" or pending.get("status") != "pending":
                        continue
                    identity = (pending.get("type"), pending.get("authority"))
                    existing = occupied.get(identity)
                    if existing is not None:
                        if self._stored_attestation_is_valid(
                            existing, expected_digest, str(pending.get("authority"))
                        ):
                            continue
                        self.breaker.open(
                            "anchor_attestation_integrity", tenant_id, payload["anchor_id"]
                        )
                        continue
                    if pending_attestation_breaker_open([pending], max_pending_seconds, now):
                        self.breaker.open(
                            "anchor_attestation_slo", tenant_id, payload["anchor_id"]
                        )
                    try:
                        result = self.provider.obtain(pending)
                    except OSError:
                        continue
                    if result.get("status") != "attested":
                        continue
                    outcome = self.repository.record_anchor_attestation(
                        tenant_id, payload["anchor_id"], result
                    )
                    if outcome == "appended":
                        completed += 1
                    elif outcome == "conflict":
                        stored = self._stored_attestation(
                            tenant_id, payload["anchor_id"], result
                        )
                        if not self._stored_attestation_is_valid(
                            stored, expected_digest, str(pending.get("authority"))
                        ):
                            self.breaker.open(
                                "anchor_attestation_integrity", tenant_id, payload["anchor_id"]
                            )
        return completed

    def _stored_attestation(
        self, tenant_id: str, anchor_id: str, candidate: dict[str, Any]
    ) -> dict[str, Any] | None:
        reader = getattr(self.repository, "anchor_attestation", None)
        if reader is None:
            return None
        return reader(tenant_id, anchor_id, candidate["authority"], candidate["type"])

    def _stored_attestation_is_valid(
        self,
        attestation: dict[str, Any] | None,
        expected_digest: str,
        expected_authority: str,
    ) -> bool:
        validator = getattr(self.provider, "attestation_validation_failure", None)
        return (
            attestation is not None
            and validator is not None
            and validator(attestation, expected_digest, expected_authority) is None
        )
