#!/usr/bin/env python3
"""Run the UC-2 Memtara -> Mizan proof-gated recommendation journey.

This is the two-product counterpart to ``demo_walk.py``.  Memtara must already
be running and initialized by its quickstart; this script invokes Memtara's
reference prover, pins the audit-chain head immediately after issuance, passes
both opaque values to Mizan, and then completes Mizan's normal approval and
single-execution flow.  ``scripts/demo.sh memtara`` wraps this journey with the
Mizan export and both offline verifiers.

The organisation API key is handed to the reference prover in its **environment**, as
``MEMTARA_ORG_API_KEY`` (``ORG_API_KEY_ENV`` below) -- never on its argv, which every local
user can read out of ``ps``.  That is a contract with the ``memtara-zkp`` repository: its
prover reads the key from that variable.

``--write-reference-transcript`` records the milestones of a **completed** walk and writes them
out, with per-run values normalised.  There is no mode that writes a transcript without running
the journey: the committed fixture is a recording or it is nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dev_pki  # noqa: E402
from demo_walk import (  # noqa: E402
    AGENT,
    CUSTOMER,
    TENANT,
    WalkFailed,
    clear_the_approval,
    context,
    recording_steps,
    redeem_and_execute,
    require,
    step,
)
from mizan_control_plane.dev_token import ensure_keypair, mint  # noqa: E402

PRODUCT_ISIN = "XS2500000018"
RECOMMEND_TOOL = "tool_product-recommendation"
ORG_API_KEY_ENV = "MEMTARA_ORG_API_KEY"

# Everything a second run of the same journey would produce differently. Each rule keeps the
# milestone and replaces only the varying value, so a step cannot be smuggled out of the
# transcript by making it look unstable.
NORMALISERS = (
    (re.compile(r"\b(adr|apr|epo|lse|vot)_[0-9a-f]+\b"), r"\1_<id>"),
    (
        re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
        "<uuid>",
    ),
    (re.compile(r"\b[0-9a-f]{16,}\b"), "<hash>"),
    (re.compile(r"\bafter \d+ attempt"), "after <n> attempt"),
    (re.compile(r"\b\d+(\.\d+)?s\b"), "<duration>"),
)


def normalise_transcript(lines: list[str]) -> list[str]:
    """Strip per-run values from recorded milestones, without dropping any milestone."""
    normalised = []
    for line in lines:
        for pattern, replacement in NORMALISERS:
            line = pattern.sub(replacement, line)
        normalised.append(line)
    return normalised


def write_reference_transcript(path: Path, lines: list[str]) -> None:
    """Write the transcript a completed walk recorded. `lines` come from `recording_steps()`."""
    require(bool(lines), "the walk recorded no milestones; there is no transcript to write")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(normalise_transcript(lines)) + "\n", encoding="utf-8")


def run_reference_prover(
    *,
    memtara_repo: Path,
    base_url: str,
    org_api_key: str,
    user_id: str,
    product_isin: str,
    vault_path: Path,
) -> dict:
    """Invoke the shipped Memtara client; do not reimplement proof generation."""
    prover = memtara_repo / "clients" / "prover" / "memtara-prove"
    if not prover.is_file():
        raise WalkFailed(f"Memtara reference prover not found: {prover}")
    command = [
        sys.executable,
        str(prover),
        "--json",
        "--quiet",
        "--base-url",
        base_url,
        "--user-id",
        user_id,
        "--product-isin",
        product_isin,
        "--vault-path",
        str(vault_path),
    ]
    # The key is a bearer credential for the whole organisation. `ps` shows argv to every local
    # user, so it travels in the child's environment instead; the reference prover reads
    # MEMTARA_ORG_API_KEY.
    environment = os.environ | {ORG_API_KEY_ENV: org_api_key}
    completed = subprocess.run(
        command, capture_output=True, text=True, cwd=memtara_repo, env=environment
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise WalkFailed(
            "Memtara reference prover failed "
            f"({completed.returncode}): {completed.stderr.strip() or completed.stdout.strip()}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise WalkFailed(f"Memtara prover returned non-JSON output: {exc}") from exc
    require(bool(result.get("proof_token")), "Memtara returned no proof token")
    require(result.get("product_isin") == product_isin, "Memtara attested the wrong ISIN")
    require(result.get("suitable") is True, "the UC-2 approval walk requires suitable=true")
    return result


def pin_chain_head(base_url: str, org_api_key: str) -> str:
    """Pin and return Memtara's head at the instant the issued token is handed off."""
    response = httpx.post(
        f"{base_url}/audit/checkpoints",
        headers={"Authorization": f"Bearer {org_api_key}"},
        timeout=30,
    )
    if response.status_code != 200:
        raise WalkFailed(f"Memtara checkpoint failed: HTTP {response.status_code}: {response.text}")
    checkpoint = response.json().get("checkpoint")
    require(isinstance(checkpoint, dict), "Memtara returned no checkpoint")
    head = checkpoint.get("head_event_hash")
    require(
        isinstance(head, str)
        and len(head) == 64
        and head == head.lower()
        and all(character in "0123456789abcdef" for character in head),
        "Memtara checkpoint returned a malformed chain head",
    )
    return head


def recommendation_context(product_isin: str) -> dict:
    return context(
        RECOMMEND_TOOL,
        "financial_write",
        ["/customer_id", "/product_isin", "/amount"],
        {"customer_id": "cus_42", "product_isin": product_isin, "amount": 250_000},
        "recommend the registered structured product after suitability assessment",
    )


def run_journey(arguments: argparse.Namespace, vault_path: Path) -> tuple[str, list[str]]:
    """Run the whole UC-2 journey, returning its decision id and the milestones it emitted.

    The milestones are recorded, not declared: whatever `step` printed is what comes back, so
    the committed transcript can only ever describe a journey that actually ran.
    """
    with recording_steps() as milestones:
        proof = run_reference_prover(
            memtara_repo=arguments.memtara_repo,
            base_url=arguments.memtara_url.rstrip("/"),
            org_api_key=arguments.memtara_org_api_key,
            user_id=arguments.memtara_user_id,
            product_isin=arguments.product_isin,
            vault_path=vault_path,
        )
        step("Memtara proof", "VERIFIED suitable=true")
        chain_head = pin_chain_head(
            arguments.memtara_url.rstrip("/"), arguments.memtara_org_api_key
        )
        step("Memtara checkpoint", f"PINNED {chain_head[:16]}…")

        private_key, _ = ensure_keypair(arguments.key_dir)
        agent_token = mint(
            private_key,
            tenant_id=TENANT,
            subject=CUSTOMER,
            agent_id=AGENT,
            identity_kind="agent",
            auth_strength="federated",
            roles=[],
            audience="mizan-control-plane",
            ttl_seconds=900,
        )
        client_kwargs: dict = {
            "base_url": arguments.api_url,
            "timeout": 15,
            "headers": {"Authorization": f"Bearer {agent_token}"},
        }
        if arguments.api_url.startswith("https://"):
            client_kwargs["verify"] = dev_pki.client_ssl_context(arguments.tls_dir)

        sent = recommendation_context(arguments.product_isin)
        with httpx.Client(**client_kwargs) as client:
            response = client.post(
                "/v1/authorize",
                json=sent,
                headers={
                    "x-memtara-proof": proof["proof_token"],
                    "x-memtara-chain-head": chain_head,
                },
            )
            require(
                response.status_code == 200,
                f"Mizan refused the verified proof: HTTP {response.status_code}: {response.text}",
            )
            decision = response.json()
            require(
                decision["decision"] == "REQUIRE_APPROVAL",
                f"proof-gated recommendation decided {decision['decision']}, "
                "expected REQUIRE_APPROVAL",
            )
            require(
                "suitability_declined" not in decision.get("reasons", []),
                "a suitable proof was classified as declined",
            )
            step("Mizan authorization", "REQUIRE_APPROVAL (proof verified and ISIN bound)")
            decision_id = clear_the_approval(client, private_key, decision)
            redeem_and_execute(
                client,
                decision_id,
                sent["tool"]["arguments"],
                arguments.receipt_timeout_seconds,
            )
    return decision_id, milestones


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Mizan + Memtara UC-2 journey")
    parser.add_argument("--api-url", default="https://127.0.0.1:8787")
    parser.add_argument("--key-dir", type=Path, default=Path("var/demo-keys"))
    parser.add_argument("--tls-dir", type=Path, default=Path("var/demo/tls"))
    parser.add_argument(
        "--memtara-repo",
        type=Path,
        default=Path(os.environ.get("MEMTARA_REPO", "../memtara-zkp")),
    )
    parser.add_argument(
        "--memtara-url",
        default=os.environ.get("MEMTARA_URL", "http://127.0.0.1:8080"),
    )
    parser.add_argument(
        "--memtara-org-api-key",
        default=os.environ.get("MEMTARA_ORG_API_KEY"),
    )
    parser.add_argument(
        "--memtara-user-id",
        default=os.environ.get("MEMTARA_USER_ID"),
    )
    parser.add_argument(
        "--vault-path",
        type=Path,
        default=Path(os.environ.get("MEMTARA_VAULT_PATH", "cro_demo/client_42_vault.json")),
    )
    parser.add_argument("--product-isin", default=PRODUCT_ISIN)
    parser.add_argument("--receipt-timeout-seconds", type=float, default=30.0)
    parser.add_argument(
        "--write-reference-transcript",
        type=Path,
        help="after the journey completes, write the milestones it recorded to this path, "
        "with per-run identifiers normalised. The walk still runs in full; a transcript is "
        "only ever a recording of one.",
    )
    arguments = parser.parse_args(argv)

    if not arguments.memtara_org_api_key or not arguments.memtara_user_id:
        parser.error(
            "--memtara-org-api-key and --memtara-user-id are required "
            "(or set MEMTARA_ORG_API_KEY and MEMTARA_USER_ID)"
        )

    vault_path = arguments.vault_path
    if not vault_path.is_absolute():
        vault_path = arguments.memtara_repo / vault_path

    try:
        decision_id, milestones = run_journey(arguments, vault_path)
    except WalkFailed as failure:
        print(f"\nUC-2 WALK FAILED: {failure}", file=sys.stderr)
        return 1

    if arguments.write_reference_transcript is not None:
        write_reference_transcript(arguments.write_reference_transcript, milestones)

    print(f"\n  decision {decision_id} is EXECUTED with one Memtara cross-anchor.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
