#!/usr/bin/env python3
"""Walk the demo agent through three tool calls and print what Mizan decided.

Two reads are allowed by policy; the rebalance requires two control domains and stops. Nothing
here is simulated: these are real HTTP calls carrying real signed tokens, and every line printed
corresponds to an ADR_Record you can fetch from /v1/decisions.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane"))

from mizan_control_plane.canonical import binding_hash  # noqa: E402
from mizan_control_plane.dev_token import ensure_keypair, mint  # noqa: E402

TENANT = "tnt_demo-bank"
AGENT = "agt_wealth-advisor"
CUSTOMER = "prn_demo-customer"

CALLS = [
    ("tool_portfolio-read", "financial_read", ["/customer_id"], {"customer_id": "cus_42"},
     "review the customer portfolio", "ALLOW"),
    ("tool_riskprofile-read", "financial_read", ["/customer_id"], {"customer_id": "cus_42"},
     "check the customer risk appetite", "ALLOW"),
    ("tool_portfolio-rebalance", "financial_write", ["/customer_id", "/amount"],
     {"customer_id": "cus_42", "amount": 250_000}, "rebalance to the target allocation",
     "REQUIRE_APPROVAL"),
]


def context(tool_id: str, action: str, bound: list[str], arguments: dict, intent: str) -> dict:
    payload = arguments | {"request_time": uuid.uuid4().hex}
    profile = "bp_" + tool_id.removeprefix("tool_").replace("_", "-") + "-v1"
    return {
        "schema_version": "1.2",
        "request_id": str(uuid.uuid4()),
        "principal": {"id": CUSTOMER, "type": "customer", "auth_strength": "mfa"},
        "agent": {"id": AGENT, "version": "1.0.0", "delegation_chain": [AGENT]},
        "intent": intent,
        "tool": {
            "id": tool_id,
            "arguments": payload,
            "parameters_hash": binding_hash(payload, bound),
            "binding_profile": {"profile_id": profile, "profile_version": 1},
        },
        "action": {"type": action},
        "resource": {
            "id": "portfolio/42",
            "type": "portfolio",
            "resource_owner": "core-banking",
            "data_classification": "financial",
        },
        "business": {"transaction_value": {"amount": 250_000, "currency": "AED"}},
        "environment": "development",
        "timestamp": "2026-08-26T00:00:00Z",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the demo agent through the control plane")
    parser.add_argument("--api-url", default="http://127.0.0.1:8787")
    parser.add_argument("--key-dir", type=Path, default=Path("var/demo-keys"))
    arguments = parser.parse_args(argv)
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
    failures = 0
    with httpx.Client(
        base_url=arguments.api_url,
        timeout=15,
        headers={"Authorization": f"Bearer {agent_token}"},
    ) as client:
        for tool_id, action, bound, payload, intent, expected in CALLS:
            response = client.post(
                "/v1/authorize", json=context(tool_id, action, bound, payload, intent)
            )
            if response.status_code != 200:
                print(f"  {tool_id:26s} HTTP {response.status_code}: {response.text}")
                failures += 1
                continue
            body = response.json()
            marker = "ok" if body["decision"] == expected else f"expected {expected}"
            failures += body["decision"] != expected
            print(
                f"  {tool_id:26s} {body['decision']:17s} {body['risk']['level']:9s} "
                f"{body['decision_id']}  {'; '.join(body['reasons'])}  [{marker}]"
            )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
