#!/usr/bin/env python3
"""R-007 / CP-B — executable reproduction of the external-anchoring findings.

This is review evidence, not product code. It lives outside `tests/` on purpose so
`pytest` does not collect it and CI does not go red on findings that are open by
design. Run it by hand:

    uv run python docs/reviews/reproductions/R-007-cpb-attestation.py

Eight cases. Two are regression guards that must never break; six are findings and
are the acceptance gate for T-049, T-050, T-051, T-055, T-057 and T-061.

| Case | Finding | Expected once fixed                                        | At 94bb25e |
|------|---------|------------------------------------------------------------|------------|
| 1    | —       | real token + real bundle + operator root verifies            | GREEN      |
| 2    | —       | an unrelated CA is rejected                                  | GREEN      |
| 3    | V-11    | a pending co-authority is NOT reported externally anchored   | RED  T-049 |
| 4    | V-14    | `obtain()` refuses to record `attested` on unvalidated bytes | RED  T-050 |
| 5    | V-12    | a missing OpenSSL fails cleanly, distinguishably, no traceback| RED  T-051 |
| 6    | V-16    | a transient TSA failure is retried, not written as terminal  | RED  T-055 |
| 7    | V-17    | an append the store refuses is never counted as a completion | RED  T-057 |
| 8    | V-19    | an ordinary concurrent double-pass is not a tamper alarm      | RED  T-061 |

**CP-B is gated on cases 1, 2, 3, 4 and 6 only.** Cases 5, 7 and 8 are real findings
whose failure mode is reporting and operations, not a false claim of external
anchoring, so R-007 §5 places them before CP-C. Exit is non-zero while any case is
open; read the summary block for which checkpoint each one blocks.

Case 6 was added by the CP-B re-run on 2026-08-26. It is a regression *introduced*
by T-050 and is invisible to case 4, which stops at the provider and never reaches
the sidecar store. Cases 4 and 6 must be read together: 4 says a bad token must not
become `attested`, 6 says it must not become permanent either.

Case 7 was added by the CP-B closeout re-run on 2026-08-26, by following T-055's fix
one call site further than case 6 reaches. T-055 is correct and case 6 is genuinely
green — but its correctness now rests on the `(anchor, authority, type)` slot being
empty, and `record_anchor_attestation` cannot tell an append from a silent refusal.
Cases 6 and 7 are the same pairing as 4 and 6: 6 says a failure must stay retryable,
7 says the retry must be able to land.

Case 8 was added by the CP-C wave-1 re-run on 2026-08-26, by following T-057's fix
one call site further than case 7 reaches. T-057 is correct and case 7 is genuinely
green. But it classifies a refused append by *byte-comparing* the stored document to
the new one, and two RFC 3161 tokens over the same imprint are never byte-identical:
each carries its own genTime, TSA serial number and optional nonce. So the "benign
idempotent race" G.13 describes is the one outcome that cannot occur, and an ordinary
concurrent double-pass — two healthy workers, two valid tokens, nothing hostile —
classifies as `conflict` and opens `anchor_attestation_integrity`. T-052 then made
the worker run continuously, which moves this from theoretical to routine. The alarm
that is supposed to mean "someone reached into the immutable evidence store" is fired
by concurrency, and an alarm that cries wolf is worse than no alarm at all.

Case 1 matters beyond its verdict: it is the only place in the tree that executes
*both* halves of the digest agreement. Every committed test stubs one side —
`test_real_rfc3161_response_verifies_offline` uses a hand-made digest, and the
mixed-anchor test monkeypatches `verify_rfc3161` with `anchor_digest: "placeholder"`.
If case 1 ever goes red, the signer and the verifier have stopped agreeing on what
they hash, and no other test in the repository will tell you.

Exit code is 0 only when all eight cases meet their post-fix expectation, so this
doubles as the CP-B and CP-C re-run gate.
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


def certificate_horizon(cert: Path) -> str:
    """The TSA certificate's `notAfter`, in the instant format the verifier compares against.

    T-091 (ADR-004 G.19, ratified after R-007 was written) made a bundle's horizon a property of
    the timestamp authority's certificate, and the verifier now refuses an `attested` sidecar that
    does not declare `expires_at` -- and refuses one whose value disagrees with the certificate.
    This reproduction pre-dates that and built its sidecars without the field, so cases 1 and 2
    went red the first time CI ran the script at all. The script was never wrong about attestation;
    it was describing an older bundle format that nothing re-checked it against.
    """
    from cryptography import x509

    return (
        x509.load_pem_x509_certificate(cert.read_bytes())
        .not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    )


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
        "expires_at": certificate_horizon(trusted),
        "anchor_digest": digest, "evidence": mint(work, config, digest),
    }
    # `expires_at` belongs to the sidecar and must NOT appear in the signed payload roster: the
    # payload is written before any TSA is contacted, so it cannot know a certificate's notAfter,
    # and the verifier refuses a roster entry that claims one.
    pending_a = {k: v for k, v in attested.items() if k != "expires_at"} | {
        "status": "pending", "obtained_at": None, "evidence": None
    }

    # --- CASE 1 · regression guard: signer and verifier agree on what they hash ---
    bundle = build_bundle(work / "case1", count=2, anchor_interval=2,
                          attestation_by_anchor={0: [pending_a]})
    rows = json.loads((bundle / "anchors.json").read_bytes())
    rows[0]["attestations"] = [attested]
    reseal(bundle, rows, {"anchor_attestation": "rfc3161", "external_timestamp": True})
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
        attestation_by_anchor={0: [pending_a, pending_b]},
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
    clean = "Traceback" not in out.stderr and out.returncode == 2
    distinguishable = "CANNOT CHECK:" in out.stderr
    record(
        "CASE 5  V-12  OpenSSL absent from PATH",
        clean and distinguishable,
        f"exit={out.returncode}; traceback={'yes' if 'Traceback' in out.stderr else 'no'}; "
        f"expected a named 'cannot check' failure distinct from 'check failed' — an auditor "
        f"must be able to tell a missing tool from bad evidence",
    )

    # --- CASE 6 · V-16 · a transient failure is written as a terminal fact -----
    # T-050 made `obtain()` return a `pending` dict instead of raising. The worker at
    # attestation.py:175 records every return value unconditionally, so one bad response
    # writes a pending sidecar into an append-only table whose primary key is
    # (tenant_id, anchor_id, authority, attestation_type) and whose INSERT is
    # ON CONFLICT DO NOTHING. The anchor can then never be attested: the worker skips it
    # as `finalized`, and the row that would replace it is silently swallowed. A network
    # blip permanently bars an anchor from satisfying I-11.
    from mizan_control_plane.attestation import AnchorAttestationWorker  # noqa: PLC0415

    class Flaky(http.server.BaseHTTPRequestHandler):
        """Garbage once, then a genuine token — an ordinary transient TSA fault."""

        attempts = 0

        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            Flaky.attempts += 1
            if Flaky.attempts == 1:
                payload = b"not-a-timestamp-token"
            else:
                query = work / f"flaky-{Flaky.attempts}.tsq"
                reply = work / f"flaky-{Flaky.attempts}.tsr"
                query.write_bytes(body)
                sh("openssl", "ts", "-reply", "-queryfile", str(query),
                   "-config", str(config), "-out", str(reply))
                payload = reply.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            return

    class SidecarStore:
        """The real table's semantics: PK (anchor, authority, type), INSERT ... DO NOTHING,
        UPDATE and DELETE revoked and rejected by trigger. See 0003_anchor_attestations.sql."""

        def __init__(self) -> None:
            self.rows: dict[tuple[str, str, str], dict] = {}

        def record_anchor_attestation(self, tenant_id: str, anchor_id: str, item: dict) -> str:
            # Mirrors evidence.py:613 after T-057: ON CONFLICT DO NOTHING, then read back
            # and classify. The classification is byte-equality, which is the point of case 8.
            key = (anchor_id, item["authority"], item["type"])
            if key not in self.rows:
                self.rows[key] = item
                return "appended"
            return "unchanged" if self.rows[key] == item else "conflict"

        def anchor_attestation(
            self, tenant_id: str, anchor_id: str, authority: str, attestation_type: str
        ) -> dict | None:
            return self.rows.get((anchor_id, authority, attestation_type))

    flaky_server = http.server.HTTPServer(("127.0.0.1", 0), Flaky)
    threading.Thread(target=flaky_server.serve_forever, daemon=True).start()
    flaky_endpoint = f"http://127.0.0.1:{flaky_server.server_address[1]}/tsr"
    store = SidecarStore()
    retry_provider = Rfc3161AnchorProvider([flaky_endpoint], trust_anchors=[trusted])
    core = {"anchor_id": "anchor-retry", "head_hash": "b" * 64, "to_sequence": 2}
    worker = AnchorAttestationWorker(
        store, retry_provider, type("B", (), {"open": lambda *a: None})()
    )
    try:
        # Two ordinary worker passes. The first meets the transient fault; the second is
        # the retry that must succeed. Nothing here is monkeypatched on either side.
        for _ in range(2):
            row = {"payload": core | {"attestations": retry_provider.attest(core)},
                   "attestations": list(store.rows.values())}
            worker.process("tnt_bank-a", [row], 900)
        final = store.rows.get(("anchor-retry", flaky_endpoint, "rfc3161"), {})
        state, why = final.get("status"), (
            f"after a transient failure and one retry the sidecar reads "
            f"{final.get('status')!r} ({final.get('failure_reason') or 'no reason'}); "
            f"{Flaky.attempts} TSA call(s) made"
        )
    except Exception as error:  # noqa: BLE001
        state, why = "error", f"{type(error).__name__}: {error}"
    finally:
        flaky_server.shutdown()
    record(
        "CASE 6  V-16  transient TSA failure, then a retry that should attest",
        state == "attested",
        f"{why}; expected the retry to attest — a failed attempt must stay retryable, "
        f"and an append-only store with ON CONFLICT DO NOTHING makes any recorded "
        f"non-terminal state permanent",
    )

    # --- CASE 7 · V-17 · an append the store refuses is counted as a completion ---
    # T-055 fixed case 6 by never writing a non-terminal sidecar, and it is correct. But
    # `record_anchor_attestation` is `INSERT ... ON CONFLICT DO NOTHING` and returns
    # nothing, so the worker cannot tell an append from a silent refusal — it increments
    # `completed` either way. T-055's correctness therefore rests on the slot being empty,
    # and nothing checks that it is. Any anchor carrying a sidecar row written by pre-fix
    # code is now hit against the TSA on EVERY pass, forever: the retry is no longer
    # skipped (T-055 removed the skip), a valid token is obtained and discarded by the
    # conflict clause, and the worker reports a completion each time.
    class Healthy(http.server.BaseHTTPRequestHandler):
        """An ordinary, entirely well-behaved TSA. Nothing is failing here but the store."""

        attempts = 0

        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            Healthy.attempts += 1
            query = work / f"healthy-{Healthy.attempts}.tsq"
            reply = work / f"healthy-{Healthy.attempts}.tsr"
            query.write_bytes(body)
            sh("openssl", "ts", "-reply", "-queryfile", str(query),
               "-config", str(config), "-out", str(reply))
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(reply.read_bytes())

        def log_message(self, *args: object) -> None:
            return

    healthy_server = http.server.HTTPServer(("127.0.0.1", 0), Healthy)
    threading.Thread(target=healthy_server.serve_forever, daemon=True).start()
    healthy_endpoint = f"http://127.0.0.1:{healthy_server.server_address[1]}/tsr"
    legacy = SidecarStore()
    legacy_provider = Rfc3161AnchorProvider([healthy_endpoint], trust_anchors=[trusted])
    legacy_core = {"anchor_id": "anchor-legacy", "head_hash": "c" * 64, "to_sequence": 3}
    # Exactly the row a pre-fix (d4d57c7) deployment left behind. Immutable, unrepairable.
    legacy.rows[("anchor-legacy", healthy_endpoint, "rfc3161")] = {
        "type": "rfc3161", "status": "pending", "authority": healthy_endpoint,
        "failure_reason": "RFC 3161 token validation failed: one transient fault, months ago",
    }
    legacy_worker = AnchorAttestationWorker(
        legacy, legacy_provider, type("B", (), {"open": lambda *a: None})()
    )
    try:
        reported = 0
        for _ in range(3):
            row = {"payload": legacy_core | {"attestations": legacy_provider.attest(legacy_core)},
                   "attestations": list(legacy.rows.values())}
            reported += legacy_worker.process("tnt_bank-a", [row], 900)
        final = legacy.rows.get(("anchor-legacy", healthy_endpoint, "rfc3161"), {})
        state, why = final.get("status"), (
            f"after 3 passes against a healthy TSA the sidecar still reads "
            f"{final.get('status')!r}; {Healthy.attempts} token(s) minted and discarded; "
            f"the worker reported {reported} completion(s)"
        )
    except Exception as error:  # noqa: BLE001
        state, reported, why = "error", 0, f"{type(error).__name__}: {error}"
    finally:
        healthy_server.shutdown()
    record(
        "CASE 7  V-17  a sidecar slot already occupied by a pre-fix pending row",
        not (reported > 0 and state != "attested"),
        f"{why}; expected the worker never to count a completion the store refused — "
        f"either the append lands or the refusal is a named integrity event, but "
        f"`INSERT ... ON CONFLICT DO NOTHING` returning nothing means neither happens",
    )

    # --- CASE 8 · V-19 · an ordinary concurrent double-pass raises a tamper alarm ---
    # T-057 made the refused append visible and classifies it by comparing the stored
    # document to the new one. ADR-004 G.13 calls an identical document "a benign
    # idempotent race" — but an RFC 3161 token carries its own genTime, TSA serial and
    # optional nonce, so two tokens over the SAME imprint are never byte-identical. The
    # benign branch is therefore unreachable for `rfc3161`, and the only surviving
    # classification for a concurrent double-pass is `conflict`, which opens the
    # `anchor_attestation_integrity` breaker. Nothing here is hostile: two healthy
    # workers, two valid tokens, one slot. There is no lease on the anchor
    # (no `FOR UPDATE SKIP LOCKED` on the pending-anchor read), and T-052 now runs the
    # worker continuously, so the stale-snapshot window is open on every pass.
    class Racer(http.server.BaseHTTPRequestHandler):
        """A second entirely well-behaved TSA. Every token it mints is valid."""

        attempts = 0

        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            Racer.attempts += 1
            query = work / f"race-{Racer.attempts}.tsq"
            reply = work / f"race-{Racer.attempts}.tsr"
            query.write_bytes(body)
            sh("openssl", "ts", "-reply", "-queryfile", str(query),
               "-config", str(config), "-out", str(reply))
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(reply.read_bytes())

        def log_message(self, *args: object) -> None:
            return

    race_server = http.server.HTTPServer(("127.0.0.1", 0), Racer)
    threading.Thread(target=race_server.serve_forever, daemon=True).start()
    race_endpoint = f"http://127.0.0.1:{race_server.server_address[1]}/tsr"
    racer = SidecarStore()
    race_provider = Rfc3161AnchorProvider([race_endpoint], trust_anchors=[trusted])
    race_core = {"anchor_id": "anchor-race", "head_hash": "d" * 64, "to_sequence": 4}
    alarms: list[str] = []
    race_worker = AnchorAttestationWorker(
        racer, race_provider, type("B", (), {"open": lambda *a: alarms.append(a[1])})()
    )
    try:
        # Worker A wins the race: it obtains a valid token and appends it. Ordinary work.
        first_pending = next(item for item in race_provider.attest(race_core)
                             if item.get("type") == "rfc3161")
        won = race_provider.obtain(first_pending)
        racer.record_anchor_attestation("tnt_bank-a", "anchor-race", won)
        # Worker B read the sidecars BEFORE A committed, so its snapshot is empty. That
        # read-then-TSA-round-trip-then-append window is seconds wide and unguarded.
        stale = {"payload": race_core | {"attestations": race_provider.attest(race_core)},
                 "attestations": []}
        race_worker.process("tnt_bank-a", [stale], 900)
        stored = racer.rows.get(("anchor-race", race_endpoint, "rfc3161"), {})
        why = (
            f"two healthy workers, two valid tokens, one slot; the stored token is "
            f"{'unchanged' if stored == won else 'the one A appended'} and the alarms "
            f"raised were {alarms or 'none'}"
        )
    except Exception as error:  # noqa: BLE001
        alarms, why = ["error"], f"{type(error).__name__}: {error}"
    finally:
        race_server.shutdown()
    record(
        "CASE 8  V-19  two healthy workers attest the same anchor concurrently",
        "anchor_attestation_integrity" not in alarms,
        f"{why}; expected no tamper alarm — `anchor_attestation_integrity` must mean "
        f"someone reached into the immutable store, and byte-equality cannot mean that "
        f"when every RFC 3161 token carries a fresh genTime, serial and nonce",
    )

    failed = [case for case, passed, _ in results if not passed]
    cpb_blockers = [case for case in failed
                    if case.split("  ")[0] in {"CASE 1", "CASE 2", "CASE 3", "CASE 4", "CASE 6"}]
    print("=" * 78)
    print(f"{len(results) - len(failed)}/{len(results)} cases at their post-fix expectation.")
    if failed:
        print("Open: " + ", ".join(case.split("  ")[0] + " " + case.split("  ")[1]
                                   for case in failed))
    print(
        "CP-B does not pass while cases 1, 2, 3, 4 or 6 are red "
        "(R-007 §5, amended by the re-runs): " + ("HELD" if cpb_blockers else "PASSED")
    )
    if failed and not cpb_blockers:
        print("Remaining cases are pre-CP-C findings, not CP-B blockers.")
    return 1 if failed else 0


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="mizan-cpb-") as directory:
        sys.exit(main(Path(directory)))
