"""What the audit commitment key actually costs, and where that cost lands (T-054, B-30).

B-30 was ruled on a stated premise: N+1 backend round trips per audit write is acceptable *because*
`AuditTrail` is the everything-else ledger and is off the authorization hot path. The ruling said to
verify that rather than assume it, and this is the verification. Two questions, and they want
different instruments.

**"Is it off the hot path?" is structural, not statistical.** There is no call edge from
`/v1/authorize` to `EvidenceRepository.append_audit`, so a latency benchmark of that path would be
measuring an edge that does not exist and would report a reassuring zero for the wrong reason. What
is worth having instead is a *gate* — `tests/unit/test_audit_commitment_cost.py` asserts the absence
of the edge, so that if T-146's wiring, or anything after it, puts an audit write on the
authorization path, that assertion fails rather than this premise quietly expiring.

**"Is it really N+1?" is a count, and counts can be wrong.** This measures the real `Redactor`
against a MAC key that counts its calls, for a payload with a known number of findings. If the
redactor MACs per field rather than per finding, or twice per finding, the ruling was priced against
the wrong number and this says so before T-146 depends on it.

The wall-clock figure here is the *local* HMAC cost only. It is deliberately not presented as the
production cost: under `custody=kms` each of these becomes a Vault round trip, and a round trip is
three to four orders of magnitude more expensive than a local `hmac.new`. The number that matters
for capacity is the count, not the microseconds, which is why the count is what is asserted.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import time
from typing import Any

from mizan_security.redaction import RedactionPolicy, Redactor, RuleBasedDlpScanner

from benchmarks.artifacts import write_artifact


class CountingMacKey:
    """A `MacKey` that answers honestly and remembers how often it was asked."""

    key_id = "bench://audit-commitment#v1"
    role = "audit-commitment"

    def __init__(self) -> None:
        self.calls = 0
        self._secret = hashlib.sha256(b"benchmark").digest()

    def mac(self, payload: bytes) -> bytes:
        self.calls += 1
        return hmac.new(self._secret, payload, hashlib.sha256).digest()


def measure(findings: int, iterations: int) -> dict[str, Any]:
    """Drive the **real** `Redactor` and count what it actually asks the key for.

    Standing rule 12: a cross-check between two copies of one expression is not a cross-check. An
    earlier draft of this benchmark encoded `N` values plus the payload itself and called that N+1,
    which would have asserted the ruling's premise against a reimplementation of the premise. The
    only honest instrument is the redactor that will do the work.
    """
    key = CountingMacKey()
    policy = RedactionPolicy(
        policy_id="dlp_benchmark-v1",
        version=1,
        content_hash="b" * 64,
        transformations={"pii": "mask", "secret": "drop", "financial": "tokenize"},
    )
    redactor = Redactor(RuleBasedDlpScanner(), key, lambda _event: None)
    # `email` is one of the scanner's sensitive keys, so each of these is exactly one finding.
    payload: dict[str, Any] = {
        f"holder_{index}": {"email": f"person-{index}@example.test"} for index in range(findings)
    }

    observed = redactor.redact(payload, policy)
    per_payload = key.calls
    if len(observed.redaction["manifest"]) != findings:
        raise RuntimeError(
            f"the scanner found {len(observed.redaction['manifest'])} findings, not {findings}; "
            "the benchmark is measuring a different payload than it claims"
        )

    key.calls = 0
    started = time.perf_counter()
    for _ in range(iterations):
        redactor.redact(payload, policy)
    elapsed = time.perf_counter() - started

    per_write = key.calls / iterations
    if per_write != per_payload:
        raise RuntimeError("the redactor's MAC count is not stable across runs")
    return {
        "findings_per_payload": findings,
        "iterations": iterations,
        "mac_calls_total": key.calls,
        "mac_calls_per_audit_write": per_write,
        "expected_n_plus_one": findings + 1,
        "matches_n_plus_one": per_write == findings + 1,
        "local_redaction_seconds_total": round(elapsed, 6),
        "local_microseconds_per_audit_write": round(elapsed / iterations * 1_000_000, 3),
        # Local HMAC only. Under `custody=kms` each of these becomes a Vault round trip, which is
        # three to four orders of magnitude more expensive -- so the count is the capacity number,
        # not the microseconds.
        "measures_kms_round_trips": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=20_000)
    args = parser.parse_args(argv)

    measurements = measure(args.findings, args.iterations)
    path = write_artifact(
        "audit-commitment",
        measurements,
        {"findings": args.findings, "iterations": args.iterations},
    )
    print(f"wrote {path}")
    print(
        f"{measurements['mac_calls_per_audit_write']} MACs per audit write "
        f"for {args.findings} findings (N+1 = {measurements['expected_n_plus_one']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
