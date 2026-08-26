#!/usr/bin/env python3
"""R-007 / CP-B — executable reproduction of the external-anchoring findings.

This is review evidence, not product code. It lives outside `tests/` on purpose so
`pytest` does not collect it and CI does not go red on findings that are open by
design. Run it by hand:

    uv run python docs/reviews/reproductions/R-007-cpb-attestation.py

Five cases. Two are regression guards that must never break; three are the open
findings and are the acceptance gate for T-049, T-050 and T-051.

| Case | Finding | Expected once fixed                                        | At 94bb25e |
|------|---------|------------------------------------------------------------|------------|
| 1    | —       | real token + real bundle + operator root verifies            | GREEN      |
| 2    | —       | an unrelated CA is rejected                                  | GREEN      |
| 3    | V-11    | a pending co-authority is NOT reported externally anchored   | RED  T-049 |
| 4    | V-14    | `obtain()` refuses to record `attested` on unvalidated bytes | RED  T-050 |
| 5    | V-12    | a missing OpenSSL fails cleanly, distinguishably, no traceback| RED  T-051 |

Case 1 matters beyond its verdict: it is the only place in the tree that executes
*both* halves of the digest agreement. Every committed test stubs one side —
`test_real_rfc3161_response_verifies_offline` uses a hand-made digest, and the
mixed-anchor test monkeypatches `verify_rfc3161` with `anchor_digest: "placeholder"`.
If case 1 ever goes red, the signer and the verifier have stopped agreeing on what
they hash, and no other test in the repository will tell you.

Exit code is 0 only when all five cases meet their post-fix expectation, so this
doubles as the CP-B re-run gate.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "control-plane"))

import rfc8785  # noqa: E402

from tests.unit.test_evidence_export import build_bundle  # noqa: E402

VERIFIER = ROOT / "scripts" / "verify_evidence_export.py"
results: list[tuple[str, bool, str]] = []


def sh(*command: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, check=True, capture_output=True)


def record(case: str, passed: bool, detail: str) -> None:
    results.append((case, passed, detail))
    print(f"  {'GREEN' if passed else 'RED  '}  {case}\n         {detail}\n")


def run_verifier(bundle: Path, *extra: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(bundle), *extra],
        capture_output=True,
        text=True,
        env=env,
    )


def make_tsa(work: Path, name: str) -> tuple[Path, Path]:
    """A local standards-compliant timestamp authority: (certificate, openssl config)."""
    key, cert, config, serial = (work / f"{name}{s}" for s in (".key", ".pem", ".cnf", ".srl"))
    serial.write_text("01\n", encoding="utf-8")
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
       "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", f"/CN={name}",
       "-addext", "extendedKeyUsage=critical,timeStamping")
    config.write_text("\n".join([
        "[tsa]", "default_tsa=tsa_config1", "[tsa_config1]", f"serial={serial}",
        "crypto_device=builtin", f"signer_cert={cert}", f"certs={cert}", f"signer_key={key}",
        "signer_digest=sha256", "default_policy=1.2.3.4.1", "digests=sha256",
        "accuracy=secs:1", "ordering=yes", "tsa_name=yes", "ess_cert_id_chain=no",
    ]), encoding="utf-8")
    return cert, config


def mint(work: Path, config: Path, digest: str) -> str:
    """A real TSA round trip over `digest`, exactly as Rfc3161AnchorProvider.obtain does."""
    query, reply = work / f"{digest[:8]}.tsq", work / f"{digest[:8]}.tsr"
    sh("openssl", "ts", "-query", "-digest", digest, "-sha256", "-cert", "-out", str(query))
    sh("openssl", "ts", "-reply", "-queryfile", str(query), "-config", str(config),
       "-out", str(reply))
    return base64.b64encode(reply.read_bytes()).decode()


def anchor_core_digest(bundle: Path) -> str:
    """The digest the VERIFIER independently reconstructs — not the one the signer claims."""
    row = json.loads((bundle / "anchors.json").read_bytes())[0]
    core = {k: v for k, v in row["payload"].items()
            if k not in {"attestations", "object_key", "object_version"}}
    return hashlib.sha256(rfc8785.dumps(core)).hexdigest()


def reseal(bundle: Path, rows: list[dict], assurance: dict) -> None:
    """Rewrite anchors.json and re-seal the manifest, as an operator export would."""
    (bundle / "anchors.json").write_bytes(rfc8785.dumps(rows))
    manifest = json.loads((bundle / "manifest.json").read_bytes())
    manifest["files"]["anchors.json"] = hashlib.sha256(
        (bundle / "anchors.json").read_bytes()
    ).hexdigest()
    manifest["assurance"] = assurance
    (bundle / "manifest.json").write_bytes(rfc8785.dumps(manifest))


def main(work: Path) -> int:
    trusted, config = make_tsa(work, "cpb-trusted-tsa")
    probe = build_bundle(work / "probe", count=2, anchor_interval=2)
    digest = anchor_core_digest(probe)
    print(f"verifier-side anchor core digest = {digest}\n")

    attested = {
        "type": "rfc3161", "status": "attested", "authority": "http://tsa-a.local/tsr",
        "requested_at": "2026-08-26T04:59:00Z", "obtained_at": "2026-08-26T05:00:00Z",
        "anchor_digest": digest, "evidence": mint(work, config, digest),
    }

    # --- CASE 1 · regression guard: signer and verifier agree on what they hash ---
    bundle = build_bundle(work / "case1", count=2, anchor_interval=2,
                          attestation_by_anchor={0: [attested]})
    out = run_verifier(bundle, "--tsa-trust-anchor", str(trusted))
    record(
        "CASE 1  real token, real bundle, operator trust root",
        out.returncode == 0 and "ATTESTATION: RFC3161" in out.stdout.upper()
        and "LIMITATION" not in out.stdout.upper(),
        f"exit={out.returncode}; expected PASS with RFC3161 and the limitation withdrawn",
    )

    # --- CASE 2 · regression guard: forgery detection is real, not decorative ---
    untrusted, _ = make_tsa(work, "unrelated-ca")
    out = run_verifier(bundle, "--tsa-trust-anchor", str(untrusted))
    record(
        "CASE 2  same bundle, unrelated certificate authority",
        out.returncode != 0 and "FAIL:" in out.stderr,  # the verifier writes FAIL: to stderr
        f"exit={out.returncode}; stderr={out.stderr.strip().splitlines()[:1]}; "
        f"expected FAIL — a token must not verify under a root that did not issue it",
    )

    # --- CASE 3 · V-11 · a pending co-authority is dropped by the `or` ---------
    # Both authorities are named in the MIZAN-SIGNED payload. Only authority A has a
    # sidecar row. `row.get("attestations") or payload.get("attestations")` discards
    # authority B's signed pending marker the moment any sidecar row exists.
    pending_b = {
        "type": "rfc3161", "status": "pending", "authority": "http://tsa-b.local/tsr",
        "requested_at": "2026-08-26T04:59:00Z", "obtained_at": None,
        "anchor_digest": digest, "evidence": None,
    }
    mixed = build_bundle(
        work / "case3", count=2, anchor_interval=2,
        attestation_by_anchor={0: [attested | {"status": "pending", "evidence": None,
                                               "obtained_at": None}, pending_b]},
    )
    rows = json.loads((mixed / "anchors.json").read_bytes())
    rows[0]["attestations"] = [attested]  # authority A completes; payload untouched
    reseal(mixed, rows, {"anchor_attestation": "rfc3161", "external_timestamp": True})
    out = run_verifier(mixed, "--tsa-trust-anchor", str(trusted))
    # The contract, not a proxy for it: an incomplete stream must not derive rfc3161
    # assurance, and the hostile-party limitation must stand.
    claims_external = ("ASSURANCE DERIVED: rfc3161" in out.stdout
                       and "LIMITATION" not in out.stdout.upper())
    record(
        "CASE 3  V-11  authority A attested, authority B still pending in the signed payload",
        not claims_external,
        f"exit={out.returncode}; ADR-004 G.11: a mixed stream is never described as externally "
        f"anchored. The signed payload names both authorities and is the authoritative roster.",
    )

    # --- CASE 4 · V-14 · `attested` is recorded on whatever bytes come back ----
    from mizan_control_plane.attestation import Rfc3161AnchorProvider  # noqa: PLC0415

    class Junk(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            # Drain the query first: an unread body resets the connection, and a
            # ConnectionResetError would pass this case for entirely the wrong reason.
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(b"not-a-timestamp-token")

        def log_message(self, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Junk)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/tsr"
    provider = Rfc3161AnchorProvider([endpoint])
    try:
        obtained = provider.obtain(provider.attest({"head_hash": "a" * 64})[0])
        status, why = obtained["status"], f"recorded status={obtained['status']!r}"
    except Exception as error:  # a refusal is the correct outcome
        status, why = "refused", f"refused with {type(error).__name__}: {error}"
    finally:
        server.shutdown()
    record(
        "CASE 4  V-14  TSA returns twenty-one bytes of garbage",
        status != "attested",
        f"{why}; expected the token to be validated against a configured root before "
        f"`attested` is written — a failed token stays `pending` with a named reason",
    )

    # --- CASE 5 · V-12 · `cannot check` must not read as `check failed` -------
    out = run_verifier(bundle, "--tsa-trust-anchor", str(trusted),
                       env=dict(os.environ, PATH="/nonexistent"))
    clean = "Traceback" not in out.stderr and out.returncode != 0
    distinguishable = "token verification failed" not in (out.stdout + out.stderr).lower()
    record(
        "CASE 5  V-12  OpenSSL absent from PATH",
        clean and distinguishable,
        f"exit={out.returncode}; traceback={'yes' if 'Traceback' in out.stderr else 'no'}; "
        f"expected a named 'cannot check' failure distinct from 'check failed' — an auditor "
        f"must be able to tell a missing tool from bad evidence",
    )

    failed = [case for case, passed, _ in results if not passed]
    print("=" * 78)
    print(f"{len(results) - len(failed)}/{len(results)} cases at their post-fix expectation.")
    if failed:
        print("Open: " + ", ".join(case.split("  ")[0] + " " + case.split("  ")[1]
                                   for case in failed))
        print("CP-B does not pass while cases 3 or 4 are red (R-007 §5).")
    return 1 if failed else 0


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="mizan-cpb-") as directory:
        sys.exit(main(Path(directory)))
