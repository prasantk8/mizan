"""What a Mizan bundle claims after its timestamp authority's certificate expires.

The founder's ruling of 2026-08-27 is that a bundle claims offline verifiability for the lifetime
of the timestamp authority's certificate and no longer. That is a smaller claim than "verifiable
forever", and it is the one we can keep — but only if the bundle says so, the verifier says so, and
the day it arrives is not reported as evidence tampering. These tests are those three sentences.

`tests/fixtures/evidence_export/expired/` is signed by a certificate whose validity window closed
on 2016-01-01 and cannot reopen. It is the only reason the post-horizon path is still tested on any
day but the day someone remembered to look.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import rfc8785
from mizan_control_plane.attestation import (
    AnchorAttestationWorker,
    Rfc3161AnchorProvider,
    timestamp_horizon,
)

from scripts.verify_evidence_export import (
    MalformedBundle,
    VerificationFailure,
    declared_horizon,
    verify_bundle,
)

EXPIRED = Path("tests/fixtures/evidence_export/expired")
ATTESTED = Path("tests/fixtures/evidence_export/attested")
PUBLIC = Path("tests/fixtures/evidence_export/public-tsa")
INSTANT = "%Y-%m-%dT%H:%M:%SZ"


def run_verifier(bundle: Path, *trust_roots: Path) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "scripts/verify_evidence_export.py", str(bundle)]
    for root in trust_roots:
        command.extend(["--tsa-trust-anchor", str(root)])
    return subprocess.run(command, check=False, capture_output=True, text=True)


def copy_bundle(fixture: Path, destination: Path) -> Path:
    bundle = destination / "bundle"
    bundle.mkdir(parents=True)
    for source in (fixture / "bundle").iterdir():
        bundle.joinpath(source.name).write_bytes(source.read_bytes())
    return bundle


def rewrite_anchors(bundle: Path, mutate) -> None:
    anchors = json.loads((bundle / "anchors.json").read_bytes())
    mutate(anchors)
    (bundle / "anchors.json").write_bytes(rfc8785.dumps(anchors))
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    for name in manifest["files"]:
        manifest["files"][name] = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
    (bundle / "manifest.json").write_bytes(rfc8785.dumps(manifest))


def token_of(fixture: Path) -> bytes:
    anchors = json.loads((fixture / "bundle" / "anchors.json").read_bytes())
    return base64.b64decode(anchors[0]["attestations"][0]["evidence"])


def test_a_bundle_past_its_horizon_is_not_reported_as_altered_evidence() -> None:
    result = run_verifier(EXPIRED / "bundle", EXPIRED / "tsa-root.pem")
    assert result.returncode == 4, result.stderr
    assert result.stdout.startswith("EXPIRED:")
    # The pre-fix answer, which this rejects: `FAIL: RFC 3161 TSA certificate is expired`, exit 1,
    # the same verdict an altered record gets.
    assert "FAIL:" not in result.stderr
    assert "2016-01-01T00:00:00Z" in result.stdout


def test_expiry_does_not_stop_the_chain_receipts_and_anchors_from_verifying() -> None:
    result = verify_bundle(EXPIRED / "bundle", [EXPIRED / "tsa-root.pem"])
    assert result["derived_assurance"] == "expired"
    assert result["records"] == 2
    assert result["anchors"] == 1
    assert result["horizon"] == "2016-01-01T00:00:00Z"
    # Reaching here at all is the claim: every hash-chain, receipt-signature and anchor-signature
    # check raises rather than returns, so a returned result is those checks having passed.


def test_a_bundle_states_the_date_it_stops_verifying_on_the_day_it_is_handed_over() -> None:
    result = run_verifier(ATTESTED / "bundle", ATTESTED / "tsa-root.pem")
    assert result.returncode == 0, result.stderr
    dates = subprocess.run(
        ["openssl", "x509", "-in", str(ATTESTED / "tsa-root.pem"), "-noout", "-enddate"],
        check=True, capture_output=True, text=True,
    ).stdout.strip().removeprefix("notAfter=")
    expected = datetime.strptime(dates, "%b %d %H:%M:%S %Y GMT").strftime(INSTANT)
    assert f"TIMESTAMP HORIZON: {expected}" in result.stdout


def test_the_declared_horizon_is_the_date_verification_actually_flips() -> None:
    """Cross-check against OpenSSL's own path validation rather than against a second copy of ours.

    The horizon here is computed by walking the token's certificates in Python. The check is that
    `openssl ts -verify` — which knows nothing about that walk — accepts one second before it and
    refuses one second after.
    """
    horizon = declared_horizon(token_of(EXPIRED))
    assert horizon == datetime(2016, 1, 1, tzinfo=UTC)
    anchors = json.loads((EXPIRED / "bundle" / "anchors.json").read_bytes())
    digest = anchors[0]["attestations"][0]["anchor_digest"]
    token = Path("/tmp") / "mizan-horizon-probe.tsr"
    token.write_bytes(token_of(EXPIRED))
    verdicts = []
    for moment in (horizon - timedelta(seconds=1), horizon + timedelta(seconds=1)):
        completed = subprocess.run(
            [
                "openssl", "ts", "-verify", "-attime", str(int(moment.timestamp())),
                "-in", str(token), "-digest", digest,
                "-CAfile", str(EXPIRED / "tsa-root.pem"),
            ],
            check=False, capture_output=True, text=True,
        )
        verdicts.append(completed.returncode == 0)
    token.unlink()
    assert verdicts == [True, False]


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        (
            "the timestamp binds a different anchor",
            lambda anchors: anchors[0]["attestations"][0].__setitem__("anchor_digest", "b" * 64),
        ),
        (
            "the token itself was edited",
            lambda anchors: anchors[0]["attestations"][0].__setitem__(
                "evidence",
                base64.b64encode(
                    bytes(
                        byte ^ (1 if index == 600 else 0)
                        for index, byte in enumerate(
                            base64.b64decode(anchors[0]["attestations"][0]["evidence"])
                        )
                    )
                ).decode(),
            ),
        ),
    ],
)
def test_an_altered_bundle_past_the_horizon_is_still_reported_as_altered(
    tmp_path: Path, name: str, mutate
) -> None:
    """EXPIRED must not become somewhere for a real defect to hide."""
    bundle = copy_bundle(EXPIRED, tmp_path)
    rewrite_anchors(bundle, mutate)
    result = run_verifier(bundle, EXPIRED / "tsa-root.pem")
    assert result.returncode == 1, f"{name}: {result.stdout}{result.stderr}"
    assert "FAIL:" in result.stderr


def test_a_bundle_past_its_horizon_under_the_wrong_trust_root_is_a_failure_not_an_expiry() -> None:
    result = run_verifier(EXPIRED / "bundle", ATTESTED / "tsa-root.pem")
    assert result.returncode == 1, result.stdout
    assert "not trusted by the operator-supplied root" in result.stderr


def test_a_sidecar_that_does_not_declare_its_expiry_is_malformed(tmp_path: Path) -> None:
    bundle = copy_bundle(ATTESTED, tmp_path)
    rewrite_anchors(bundle, lambda anchors: anchors[0]["attestations"][0].pop("expires_at"))
    with pytest.raises(MalformedBundle, match="does not declare expires_at"):
        verify_bundle(bundle, [ATTESTED / "tsa-root.pem"])


def test_a_sidecar_that_overstates_its_expiry_is_rejected(tmp_path: Path) -> None:
    """The declared date is a caption, so the verdict never rests on it."""
    bundle = copy_bundle(EXPIRED, tmp_path)
    rewrite_anchors(
        bundle,
        lambda anchors: anchors[0]["attestations"][0].__setitem__(
            "expires_at", "2099-01-01T00:00:00Z"
        ),
    )
    with pytest.raises(VerificationFailure, match="misstates its own expiry"):
        verify_bundle(bundle, [EXPIRED / "tsa-root.pem"])


def test_the_signed_roster_cannot_declare_an_expiry_it_could_not_have_known(
    tmp_path: Path,
) -> None:
    bundle = copy_bundle(ATTESTED, tmp_path)
    rewrite_anchors(
        bundle,
        lambda anchors: anchors[0]["payload"]["attestations"][0].__setitem__(
            "expires_at", "2036-01-01T00:00:00Z"
        ),
    )
    with pytest.raises(MalformedBundle, match="roster is written before any token exists"):
        verify_bundle(bundle, [ATTESTED / "tsa-root.pem"])


def test_a_horizon_is_the_last_authority_standing_and_not_the_first_to_go() -> None:
    """Two authorities on one anchor: countersigning bought time, and the report has to show it."""
    anchors = json.loads((PUBLIC / "bundle" / "anchors.json").read_bytes())
    declared = sorted(item["expires_at"] for item in anchors[0]["attestations"])
    assert len(declared) == 2 and declared[0] < declared[1]
    result = verify_bundle(
        PUBLIC / "bundle",
        [PUBLIC / "freetsa-root.pem", PUBLIC / "usertrust-rsa-root.pem"],
    )
    assert result["horizon"] == declared[1]


def test_the_control_plane_and_the_offline_verifier_read_the_same_horizon() -> None:
    """Two copies of one rule, kept in step.

    Not an independent confirmation — the rule is written twice because the offline verifier is a
    two-dependency standalone script that cannot import this package. T-062's sealed second
    implementation is the thing that would confirm it. What this catches is the two drifting.
    """
    tokens = [token_of(EXPIRED), token_of(ATTESTED)]
    for row in json.loads((PUBLIC / "bundle" / "anchors.json").read_bytes()):
        tokens.extend(base64.b64decode(item["evidence"]) for item in row["attestations"])
    assert len(tokens) == 4
    for token in tokens:
        assert timestamp_horizon(token) == declared_horizon(token) is not None


def test_a_freshly_issued_token_signed_with_an_expired_certificate_is_refused() -> None:
    """An authority handing out already-expired tokens is a supplier problem, caught on arrival."""
    token = token_of(EXPIRED)
    anchors = json.loads((EXPIRED / "bundle" / "anchors.json").read_bytes())
    digest = anchors[0]["attestations"][0]["anchor_digest"]

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return token

    provider = Rfc3161AnchorProvider(
        ["https://tsa.example.test"], [EXPIRED / "tsa-root.pem"]
    )
    provider_module = sys.modules["mizan_control_plane.attestation"]
    original = provider_module.urllib.request.urlopen
    provider_module.urllib.request.urlopen = lambda request, timeout: Response()
    try:
        result = provider.obtain({
            "type": "rfc3161", "status": "pending", "authority": "https://tsa.example.test",
            "anchor_digest": digest, "evidence": None, "obtained_at": None,
        })
    finally:
        provider_module.urllib.request.urlopen = original
    assert result["status"] == "pending"
    assert result["evidence"] is None
    assert "expired at 2016-01-01T00:00:00Z" in result["failure_reason"]


def _revalidation_alarms(stored_mutation: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
    """Run the attestation worker over an anchor whose stored token is past its horizon."""
    anchors = json.loads((EXPIRED / "bundle" / "anchors.json").read_bytes())
    payload = anchors[0]["payload"]
    stored = anchors[0]["attestations"][0] | (stored_mutation or {})
    opened: list[tuple[Any, ...]] = []
    worker = AnchorAttestationWorker(
        SimpleNamespace(
            record_anchor_attestation=lambda *args: "appended",
            anchor_attestation=lambda *args: stored,
        ),
        Rfc3161AnchorProvider(
            [payload["attestations"][0]["authority"]], [EXPIRED / "tsa-root.pem"]
        ),
        SimpleNamespace(open=lambda *args: opened.append(args)),
    )
    worker.process(
        "tnt_bank-a",
        [{"payload": payload, "attestations": [stored]}],
        900,
    )
    return opened


def test_an_expired_timestamp_does_not_raise_the_tamper_alarm() -> None:
    """R-007 fixed what `anchor_attestation_integrity` means: someone reached into the store.

    Before this change the revalidation pass asked OpenSSL whether the TSA certificate was valid
    *today*, so on the day it expired every intact attestation failed revalidation, the breaker
    opened on an integrity alarm, and ADR-003 failed the tenant's financial writes closed. Nothing
    had been touched; the certificate had simply reached its own notAfter.
    """
    assert _revalidation_alarms() == []


def test_an_expiry_edited_in_the_store_does_raise_the_tamper_alarm() -> None:
    """The counterpart, so the test above cannot pass by the check having been switched off."""
    alarms = _revalidation_alarms({"expires_at": "2099-01-01T00:00:00Z"})
    assert [name for name, *_ in alarms] == ["anchor_attestation_integrity"]
