from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from mizan_control_plane.models import MappedInput
from mizan_control_plane.policy_engine import (
    CedarPolicyEvaluator,
    PolicyCompileError,
    compile_condition,
    compile_policy,
)
from mizan_control_plane.registry import policy_semantic_hash
from mizan_control_plane.schema_validation import ContractSchemas

from tests.unit.test_authorization import context


def policy(conditions: dict, *, decision: str = "ALLOW", priority: int = 100) -> dict:
    return {
        "schema_version": "1.3",
        "policy_id": "pol_transfer",
        "tenant_id": "tnt_bank-a",
        "name": "Transfer policy",
        "version": 1,
        "status": "ACTIVE",
        "author": "risk-team",
        "applies_to": {"tool_ids": ["tool_transfer"]},
        "conditions": conditions,
        "decision": decision,
        "priority": priority,
        "content_hash": "1" * 64,
        "created_at": "2026-08-25T00:00:00Z",
    }


def test_nested_dsl_compiles_and_matches_with_explanation_identity() -> None:
    document = policy(
        {
            "all": [
                {"field": "action.type", "op": "eq", "value": "financial_write"},
                {"field": "business.transaction_value.amount", "op": "gte", "value": 10000},
                {"not": {"field": "security.blocked", "op": "present"}},
            ]
        }
    )
    matches = CedarPolicyEvaluator().evaluate([document], context())
    assert [(item.policy_id, item.version, item.content_hash) for item in matches] == [
        ("pol_transfer", 1, "1" * 64)
    ]


def test_applies_to_empty_selector_matches_nothing() -> None:
    document = policy({"field": "action.type", "op": "eq", "value": "financial_write"})
    document["applies_to"] = {"tool_ids": []}
    assert CedarPolicyEvaluator().evaluate([document], context()) == []


def test_unknown_or_unsafe_operators_fail_compilation() -> None:
    with pytest.raises(PolicyCompileError):
        compile_condition({"field": "metadata.secret", "op": "exec", "value": "x"})
    with pytest.raises(PolicyCompileError):
        compile_condition({"field": "agent.__class__", "op": "eq", "value": "x"})


def test_compiled_policy_handle_meets_hot_path_latency_budget() -> None:
    document = policy({"field": "action.type", "op": "eq", "value": "financial_write"})
    compiled = compile_policy(json.dumps(document, sort_keys=True, separators=(",", ":")))
    request = context()
    iterations = 2_000
    started = time.perf_counter()
    for _ in range(iterations):
        assert compiled.matches(request)
    elapsed = time.perf_counter() - started
    assert iterations / elapsed >= 1_000
    assert elapsed / iterations < 0.005


def test_decimal_conditions_use_cedar_decimal_extension() -> None:
    request = context()
    request.security.anomaly_score = 0.875
    document = policy({"field": "security.anomaly_score", "op": "gte", "value": 0.75})
    assert CedarPolicyEvaluator().evaluate([document], request) != []
    document["conditions"]["value"] = 0.9
    assert CedarPolicyEvaluator().evaluate([document], request) == []


def test_risk_and_environment_selectors_use_enriched_values() -> None:
    request = context()
    document = policy({"field": "action.type", "op": "eq", "value": "financial_write"})
    document["applies_to"] |= {"risk_levels": ["HIGH"], "environments": ["production"]}
    assert CedarPolicyEvaluator().evaluate([document], request, "HIGH") != []
    assert CedarPolicyEvaluator().evaluate([document], request, "LOW") == []


def test_eq_field_binds_a_verified_claim_to_the_tool_argument() -> None:
    request = context()
    request.mapped = MappedInput.model_validate({
        "source": "memtara",
        "fields": {"product_isin": "XS1234567890"},
    })
    request.tool.arguments = {"product_isin": "XS1234567890"}
    document = policy(
        {
            "field": "mapped.fields.product_isin",
            "op": "eq_field",
            "value": "tool.arguments.product_isin",
        }
    )
    assert CedarPolicyEvaluator().evaluate([document], request)
    request.tool.arguments["product_isin"] = "XS0000000000"
    assert CedarPolicyEvaluator().evaluate([document], request) == []


def test_reference_suitability_policy_is_valid_hash_bound_and_fail_closed() -> None:
    path = Path("policies/reference/require_suitability_proof.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    ContractSchemas(Path("SPEC_v1.md")).validate("Policy", document)
    assert policy_semantic_hash(document) == document["content_hash"]

    request = context()
    request.tool.id = "tool_product-recommendation"
    request.tool.arguments = {"product_isin": "XS1234567890"}
    request.action.type = "communicate"
    request.mapped = MappedInput.model_validate({
        "source": "memtara",
        "fields": {
            "proof_hash": "b" * 64,
            "circuit": "wealth_suitability",
            "predicate": "structured_product_suitable",
            "product_isin": "XS1234567890",
            "suitable": True,
            "expires_at": 1_800_000_000,
            "jti": "proof-jti-00000001",
        },
    })
    evaluator = CedarPolicyEvaluator()

    # UC-2 recommendation row: a matching valid proof permits the below-threshold tool.
    assert evaluator.evaluate([document], request)
    # No proof.
    request.mapped = None
    assert evaluator.evaluate([document], request) == []
    # A verified decline is never treated as an approval.
    request.mapped = MappedInput.model_validate({
        "source": "memtara",
        "fields": {
            "circuit": "wealth_suitability",
            "predicate": "structured_product_suitable",
            "product_isin": "XS1234567890",
            "suitable": False,
        },
    })
    assert evaluator.evaluate([document], request) == []
    # A proof about a different instrument cannot authorize this recommendation.
    request.mapped.fields["suitable"] = True
    request.mapped.fields["product_isin"] = "XS0000000000"
    assert evaluator.evaluate([document], request) == []
    # Profile reads and exports remain outside this narrowly-scoped reference policy; deployments
    # compose their ordinary read policy while export stays default-denied.
    request.tool.id = "tool_client-profile-read"
    request.action.type = "financial_read"
    assert evaluator.evaluate([document], request) == []
    request.tool.id = "tool_client-documents-export"
    request.action.type = "export"
    assert evaluator.evaluate([document], request) == []
