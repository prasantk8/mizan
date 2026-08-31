from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from mizan_control_plane.config import Settings
from mizan_control_plane.evidence import (
    Ed25519EvidenceSigner,
    EvidenceRepository,
    LocalImmutableObjectStore,
    OutboxPublisher,
)
from mizan_control_plane.models import AuthenticatedIdentity, EvaluationContext
from mizan_control_plane.repository import PostgresAuthorizationRepository
from mizan_control_plane.risk import RegistryFloorRiskProvider
from mizan_control_plane.runtime import build_runtime
from mizan_control_plane.service import AuthorizationService

from tests.support import UNUSED_IDENTITY_JWKS
from tests.unit.test_authorization import context

TENANT = "tnt_bank-b"
STREAM = "tnt_bank-b:adr:0"


def _seed_export_tenant(repository: PostgresAuthorizationRepository) -> None:
    tool = {
        "tenant_id": TENANT,
        "tool_id": "tool_transfer",
        "risk_tier": "HIGH",
        "owner": "wealth-team",
        "resource_owner": "core-banking",
        "data_classification": "financial",
        "binding_profile": {
            "profile_id": "bp_transfer-v1",
            "profile_version": 1,
            "canonicalization": "RFC8785",
            "bound_pointers": ["/amount"],
            "volatile_pointers": ["/request_time"],
            "unknown_pointer_policy": "reject",
        },
        "execution": {
            "executor_spiffe_ids": ["spiffe://mizan/executor/settlement"],
            "token_ttl_seconds": 300,
            "lease_ttl_seconds": 900,
            "heartbeat_interval_seconds": 60,
            "max_lease_extensions": 24,
        },
    }
    policy = {
        "schema_version": "1.2",
        "policy_id": "pol_export-allow",
        "tenant_id": TENANT,
        "name": "Export pipeline allow fixture",
        "version": 1,
        "status": "ACTIVE",
        "author": "risk-team",
        "applies_to": {"tool_ids": ["tool_transfer"]},
        "conditions": {"field": "action.type", "op": "eq", "value": "financial_write"},
        "decision": "ALLOW",
        "priority": 100,
        "content_hash": "4" * 64,
        "created_at": "2026-08-25T00:00:00Z",
    }
    with repository.pool.connection() as connection, connection.transaction():
        repository._scope(connection, TENANT)
        connection.execute(
            "INSERT INTO mizan.binding_profiles(tenant_id,profile_id,profile_version,canonicalization,bound_pointers,volatile_pointers,content_hash) VALUES (%s,'bp_transfer-v1',1,'RFC8785','[\"/amount\"]','[\"/request_time\"]',%s)",
            (TENANT, "1" * 64),
        )
        connection.execute(
            "INSERT INTO mizan.tools(tenant_id,tool_id,profile_id,profile_version,document) VALUES (%s,'tool_transfer','bp_transfer-v1',1,%s)",
            (TENANT, json.dumps(tool)),
        )
        connection.execute(
            "INSERT INTO mizan.agents(tenant_id,agent_id,version,lifecycle_state,document,created_at,updated_at) VALUES (%s,'agt_wealth-01','1.0.0','ACTIVE',%s,now(),now())",
            (TENANT, json.dumps({"tenant_id": TENANT, "agent_id": "agt_wealth-01"})),
        )
        connection.execute(
            "INSERT INTO mizan.agent_tools(tenant_id,agent_id,tool_id) VALUES (%s,'agt_wealth-01','tool_transfer')",
            (TENANT,),
        )
        connection.execute(
            "INSERT INTO mizan.policies(tenant_id,policy_id,version,status,effective_from,decision,content_hash,document,created_at) VALUES (%s,'pol_export-allow',1,'ACTIVE',now()-interval '1 minute','ALLOW',%s,%s,now()-interval '1 minute')",
            (TENANT, "4" * 64, json.dumps(policy)),
        )
        connection.execute(
            "INSERT INTO mizan.evidence_chain_heads(tenant_id,stream_id) VALUES (%s,%s)",
            (TENANT, STREAM),
        )


@pytest.mark.skipif(not os.getenv("MIZAN_TEST_DATABASE_URL"), reason="Postgres not configured")
def test_operator_export_verifies_and_a_missing_bucket_segment_fails_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = os.environ["MIZAN_TEST_DATABASE_URL"]
    repository = PostgresAuthorizationRepository(database_url)
    _seed_export_tenant(repository)
    principal = AuthenticatedIdentity(
        tenant_id=TENANT,
        agent_id="agt_wealth-01",
        subject="test",
        delegation_chain=["agt_wealth-01"],
    )
    for suffix in ("301", "302"):
        document = context(f"018f47a6-7b42-7c00-8000-000000000{suffix}").model_dump(mode="json")
        document["tenant_id"] = TENANT
        AuthorizationService(
            repository, RegistryFloorRiskProvider(), "integration-export", "f" * 64
        ).authorize(principal, EvaluationContext.model_validate(document))

    evidence = EvidenceRepository(database_url)
    receipt_signer = Ed25519EvidenceSigner.development("evidence-receipt")
    anchor_signer = Ed25519EvidenceSigner.development("evidence-anchor")
    object_root = tmp_path / "objects"
    publisher = OutboxPublisher(
        evidence, LocalImmutableObjectStore(object_root), receipt_signer, anchor_signer
    )
    assert publisher.drain(TENANT) == 2
    anchor = publisher.anchor(TENANT, STREAM)
    assert anchor["covered_record_count"] == 2

    keyset = tmp_path / "keys.json"
    keyset.write_text(
        json.dumps(
            [
                {
                    "key_id": item.key_id,
                    "algorithm": "Ed25519",
                    "role": role,
                    "custody": "development-derived",
                    "public_key": base64.urlsafe_b64encode(
                        item.public_key.public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw
                        )
                    ).decode(),
                    "not_before": "2026-08-25T00:00:00Z",
                    "not_after": None,
                    "revoked_at": None,
                }
                for role, item in (
                    ("evidence-receipt", receipt_signer),
                    ("evidence-anchor", anchor_signer),
                )
            ]
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "operator-bundle"
    export_pythonpath = os.getenv("MIZAN_TEST_EXPORT_PYTHONPATH", "control-plane")
    environment = os.environ | {"PYTHONPATH": export_pythonpath}
    exported = subprocess.run(
        [
            sys.executable,
            "-m",
            "mizan_control_plane.evidence_export",
            "--database-url",
            database_url,
            "--object-store",
            str(object_root),
            "--keyset",
            str(keyset),
            "--tenant-id",
            TENANT,
            "--stream-id",
            STREAM,
            "--output",
            str(bundle),
            # This pipeline signs with development custody, which T-065 made a refusal rather
            # than a printed warning. Naming the reason is the point of the flag, and the bundle
            # carries it -- asserted below, because a bundle forced out of the exporter must
            # tell its holder so.
            "--allow-development-custody",
            "integration fixture: local development keys, not evidence",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert exported.returncode == 0, exported.stderr
    assert exported.stdout.strip() == str(bundle)
    assert "WARNING: exported under development custody" in exported.stderr
    override = json.loads((bundle / "manifest.json").read_bytes())["custody_override"]
    assert override["custody"] == "development-derived"
    assert override["reason"].startswith("integration fixture")
    verified = subprocess.run(
        [sys.executable, "scripts/verify_evidence_export.py", str(bundle)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr
    assert "2 records, 1 anchors" in verified.stdout
    # The whole point of recording the override: the verifier reports it to whoever is holding
    # the bundle, without them having to know to look in the manifest.
    assert "CUSTODY OVERRIDE:" in verified.stdout

    # The production probe and the drainer use the same reconciliation implementation. First show
    # the healthy database receipts and object stream produce readiness 200, then remove the exact
    # segment those receipts address and require `/readyz` itself to fail. A unit fake returning
    # `False` here would prove only that readiness can display a false value, not that a real
    # database-to-bucket mismatch reaches it.
    monkeypatch.setenv("MIZAN_DATABASE_URL", database_url)
    monkeypatch.setenv("MIZAN_JWT_ISSUER", "https://issuer.reconciliation.test")
    monkeypatch.setenv("MIZAN_IDENTITY_JWKS", UNUSED_IDENTITY_JWKS)
    monkeypatch.setenv("MIZAN_EVIDENCE_OBJECT_STORE_ROOT", str(object_root))
    monkeypatch.setenv("MIZAN_DRAIN_TENANTS", TENANT)
    runtime = build_runtime(Settings.from_environment())
    try:
        with TestClient(runtime.app) as client:
            healthy = client.get("/readyz")
            assert healthy.status_code == 200

            object_key = evidence.receipt_rows(TENANT, STREAM)[0]["payload"]["object_key"]
            (object_root / object_key).unlink()
            mismatched = client.get("/readyz")
            assert mismatched.status_code == 503
            assert mismatched.json()["checks"]["evidence_reconciliation"] == "mismatch"
    finally:
        for pool in runtime.app.state.connection_pools:
            pool.close()
