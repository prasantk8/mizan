from __future__ import annotations

import base64
import hashlib
import subprocess
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785


class Rfc3161AnchorProvider:
    """Asynchronous RFC 3161 provider: anchor writes pending, worker obtains tokens later."""

    def __init__(self, endpoints: list[str], timeout_seconds: float = 5.0) -> None:
        if not endpoints:
            raise ValueError("at least one RFC 3161 endpoint is required")
        self.endpoints = endpoints
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
        return pending | {
            "status": "attested",
            "obtained_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "evidence": base64.b64encode(token).decode(),
        }


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
            finalized = {
                (item.get("type"), item.get("authority")) for item in row.get("attestations", [])
            }
            payload = row["payload"]
            for pending in payload.get("attestations", []):
                if pending.get("type") != "rfc3161" or pending.get("status") != "pending":
                    continue
                if (pending.get("type"), pending.get("authority")) in finalized:
                    continue
                try:
                    attested = self.provider.obtain(pending)
                except Exception:
                    if pending_attestation_breaker_open([pending], max_pending_seconds, now):
                        self.breaker.open(
                            "anchor_attestation_slo", tenant_id, payload["anchor_id"]
                        )
                    continue
                self.repository.record_anchor_attestation(
                    tenant_id, payload["anchor_id"], attested
                )
                completed += 1
        return completed
