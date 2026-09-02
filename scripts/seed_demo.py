#!/usr/bin/env python3
"""Seed the demo tenant: one agent, three tools, two ACTIVE policies.

Everything a client could do is done over HTTP against the running control plane, so `make demo`
exercises the real API rather than writing rows behind it. Only what has no API — the tenant row,
the role-authority mapping, and the evidence chain head — is written with the owner DSN.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control-plane"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dev_pki  # noqa: E402
from mizan_control_plane.canonical import canonical_hash  # noqa: E402
from mizan_control_plane.dev_token import ensure_keypair, mint  # noqa: E402

TENANT = "tnt_demo-bank"
AGENT = "agt_wealth-advisor"
AUTHOR = "prn_risk-author"
APPROVER = "prn_risk-approver"
NOW = "2026-08-26T00:00:00Z"
EXECUTOR = "spiffe://mizan-demo/executor/wealth"

APPROVER_POOL = {
    "members": [
        {"principal_id": "prn_ops-manager", "roles": ["manager"], "control_domain": "business.ops"},
        {"principal_id": "prn_risk-officer", "roles": ["risk"], "control_domain": "risk.control"},
        {
            "principal_id": "prn_compliance-officer",
            "roles": ["compliance"],
            "control_domain": "compliance.control",
        },
    ]
}


def tool(tool_id: str, *, risk: str, action: str, classification: str, bound: list[str]) -> dict:
    return {
        "schema_version": "1.2",
        "tool_id": tool_id,
        "tenant_id": TENANT,
        "name": tool_id.removeprefix("tool_").replace("_", " ").title(),
        "owner": "wealth-team",
        "risk_tier": risk,
        "action_type": action,
        "resource_owner": "core-banking",
        "data_classification": classification,
        "binding_profile": {
            "profile_id": f"bp_{tool_id.removeprefix('tool_').replace('_', '-')}-v1",
            "profile_version": 1,
            "canonicalization": "RFC8785",
            "bound_pointers": bound,
            "volatile_pointers": ["/request_time"],
            "unknown_pointer_policy": "reject",
        },
        "execution": {
            "executor_spiffe_ids": [EXECUTOR],
            "token_ttl_seconds": 300,
            "lease_ttl_seconds": 900,
            "heartbeat_interval_seconds": 60,
            "max_lease_extensions": 24,
        },
        "created_at": NOW,
    }


TOOLS = [
    tool(
        "tool_portfolio-read",
        risk="LOW",
        action="financial_read",
        classification="financial",
        bound=["/customer_id"],
    ),
    tool(
        "tool_riskprofile-read",
        risk="LOW",
        action="financial_read",
        classification="pii",
        bound=["/customer_id"],
    ),
    tool(
        "tool_portfolio-rebalance",
        risk="HIGH",
        action="financial_write",
        classification="financial",
        bound=["/customer_id", "/amount"],
    ),
    tool(
        "tool_product-recommendation",
        risk="HIGH",
        action="communicate",
        classification="financial",
        bound=["/customer_id", "/product_isin", "/amount"],
    ),
]

AGENT_DOCUMENT = {
    "schema_version": "1.1",
    "agent_id": AGENT,
    "tenant_id": TENANT,
    "name": "Wealth Advisor",
    "version": "1.0.0",
    "owner": "wealth-team",
    "accountable_owner": "head-of-wealth@demo.test",
    "purpose": "Reads a customer portfolio and proposes a rebalance",
    "environment": "development",
    "risk_tier": "HIGH",
    "lifecycle_state": "ACTIVE",
    "identity": {"auth_method": "jwt_svid", "credential_ref": "kms://demo/wealth-advisor"},
    "tools": [item["tool_id"] for item in TOOLS],
    "policies": [],
    "delegation": {
        "allowed_agent_ids": [],
        "max_delegation_depth": 0,
        "inherit_parent_permissions": False,
    },
    "created_at": NOW,
    "updated_at": NOW,
}


def policy(policy_id: str, name: str, tools: list[str], decision: str, **extra) -> dict:
    document = {
        "schema_version": "1.3",
        "policy_id": policy_id,
        "tenant_id": TENANT,
        "name": name,
        "version": 1,
        "status": "DRAFT",
        "author": AUTHOR,
        "applies_to": {"tool_ids": tools},
        "conditions": {"field": "agent.id", "op": "eq", "value": AGENT},
        "decision": decision,
        "priority": 100,
        "created_at": NOW,
        **extra,
    }
    document["content_hash"] = canonical_hash(
        {
            key: value
            for key, value in document.items()
            if key not in {"content_hash", "status", "approver", "effective_from"}
        }
    )
    return document


POLICIES = [
    policy(
        "pol_demo-read",
        "Reads are allowed",
        ["tool_portfolio-read", "tool_riskprofile-read"],
        "ALLOW",
    ),
    policy(
        "pol_demo-rebalance",
        "Rebalances need two control domains",
        ["tool_portfolio-rebalance"],
        "REQUIRE_APPROVAL",
        priority=200,
        approval_requirements={
            "quorum": 2,
            "approver_roles": ["manager", "risk"],
            "distinct_roles_required": True,
            "expiry_seconds": 3600,
            "rejection_mode": "veto",
        },
    ),
    policy(
        "pol_demo-suitability",
        "Recommendations require a verified suitable Memtara proof and supervisor quorum",
        ["tool_product-recommendation"],
        "REQUIRE_APPROVAL",
        priority=500,
        conditions={
            "all": [
                {"field": "mapped.source", "op": "eq", "value": "memtara"},
                {
                    "field": "mapped.fields.circuit",
                    "op": "eq",
                    "value": "wealth_suitability",
                },
                {
                    "field": "mapped.fields.predicate",
                    "op": "eq",
                    "value": "structured_product_suitable",
                },
                {"field": "mapped.fields.suitable", "op": "eq", "value": True},
                {
                    "field": "mapped.fields.product_isin",
                    "op": "eq_field",
                    "value": "tool.arguments.product_isin",
                },
            ]
        },
        approval_requirements={
            "quorum": 2,
            "approver_roles": ["manager", "risk"],
            "distinct_roles_required": True,
            "expiry_seconds": 3600,
            "rejection_mode": "veto",
        },
    ),
]


def seed_owner_rows(owner_dsn: str) -> None:
    with psycopg.connect(owner_dsn, autocommit=True) as connection:
        connection.execute(
            "INSERT INTO mizan.tenants(tenant_id,region,status) VALUES (%s,'ae-dubai-1','ACTIVE') "
            "ON CONFLICT DO NOTHING",
            (TENANT,),
        )
        connection.execute(
            "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s) "
            "ON CONFLICT DO NOTHING",
            (TENANT, f"{TENANT}:adr:0"),
        )
        connection.execute(
            "INSERT INTO mizan.role_authority_versions(tenant_id,mapping_version,status,document,"
            "approved_at) VALUES (%s,1,'APPROVED',%s,now()) ON CONFLICT DO NOTHING",
            (TENANT, json.dumps(APPROVER_POOL)),
        )


def operator_token(key_dir: Path, subject: str, roles: list[str]) -> str:
    private_key, _ = ensure_keypair(key_dir)
    return mint(
        private_key,
        tenant_id=TENANT,
        subject=subject,
        agent_id=AGENT,
        identity_kind="human",
        auth_strength="hardware",
        roles=roles,
        audience="mizan-control-plane",
        ttl_seconds=3600,
    )


def _post(client: httpx.Client, path: str, token: str, body: dict) -> httpx.Response:
    response = client.post(path, json=body, headers={"Authorization": f"Bearer {token}"})
    if response.status_code in {409}:
        return response
    if response.status_code >= 400:
        raise SystemExit(f"{path} failed {response.status_code}: {response.text}")
    return response


def activate(client: httpx.Client, document: dict, author: str, approver: str) -> None:
    policy_id, version = document["policy_id"], document["version"]
    simulation_context = {
        "schema_version": "1.2",
        "request_id": "018f47a6-7b42-7c00-8000-0000000000aa",
        "principal": {
            "id": "prn_demo-customer",
            "type": "customer",
            "auth_strength": "mfa",
        },
        "agent": {"id": AGENT, "version": "1.0.0", "delegation_chain": [AGENT]},
        "intent": "seed simulation",
        "tool": {
            "id": document["applies_to"]["tool_ids"][0],
            "arguments": {},
            "parameters_hash": "0" * 64,
            "binding_profile": {"profile_id": "bp_portfolio-read-v1", "profile_version": 1},
        },
        "action": {"type": "financial_read"},
        "resource": {
            "id": "portfolio/demo",
            "type": "portfolio",
            "resource_owner": "core-banking",
            "data_classification": "financial",
        },
        "environment": "development",
        "timestamp": NOW,
    }
    _post(
        client,
        f"/v1/policies/{policy_id}/simulate",
        author,
        {"version": version, "context": simulation_context},
    )
    for actor, target in ((author, "TESTED"), (approver, "APPROVED"), (approver, "ACTIVE")):
        _post(
            client,
            f"/v1/policies/{policy_id}/transition",
            actor,
            {"version": version, "target_status": target},
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the Mizan demo tenant")
    parser.add_argument("--api-url", default="http://127.0.0.1:8080")
    parser.add_argument("--owner-database-url", required=True)
    parser.add_argument("--key-dir", type=Path, default=Path("var/demo-keys"))
    parser.add_argument(
        "--tls-dir",
        type=Path,
        help="the development PKI from scripts/dev_pki.py. The demo control plane serves mutual "
        "TLS -- execution endpoints require a verified peer SPIFFE identity -- and a listener "
        "with a client CA configured demands a certificate on every connection, seeding and "
        "/health/ready included. Omit for a plain-HTTP control plane.",
    )
    arguments = parser.parse_args(argv)

    seed_owner_rows(arguments.owner_database_url)
    author = operator_token(arguments.key_dir, AUTHOR, ["registry.admin", "risk"])
    approver = operator_token(arguments.key_dir, APPROVER, ["registry.admin", "manager"])
    client_kwargs: dict = {"base_url": arguments.api_url, "timeout": 15}
    if arguments.tls_dir is not None:
        client_kwargs["verify"] = dev_pki.client_ssl_context(arguments.tls_dir)
    with httpx.Client(**client_kwargs) as client:
        # Tools first: mizan.agent_tools has a foreign key to both sides, and the agent document
        # is the side that names the permission, so the tools must already exist.
        for document in TOOLS:
            _post(client, "/v1/tools", author, document)
        _post(client, "/v1/agents", author, AGENT_DOCUMENT)
        for document in POLICIES:
            _post(client, "/v1/policies", author, document)
            activate(client, document, author, approver)
    print(
        f"seeded {TENANT}: agent {AGENT}, {len(TOOLS)} tools, {len(POLICIES)} ACTIVE policies "
        f"at {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
