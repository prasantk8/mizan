from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import cedarpy

from .models import EvaluationContext, PolicyMatch


class PolicyCompileError(ValueError):
    pass


_SAFE_SEGMENT = re.compile(r"^[a-z][a-z0-9_]*$")


def _literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(_literal(item) for item in value) + "]"
    raise PolicyCompileError(f"unsupported Cedar literal type: {type(value).__name__}")


def _path(field: str) -> str:
    segments = field.split(".")
    if not segments or any(not _SAFE_SEGMENT.fullmatch(segment) for segment in segments):
        raise PolicyCompileError(f"unsafe evaluation field: {field}")
    return "context.mizan." + ".".join(segments)


def _present_expression(field: str) -> str:
    segments = field.split(".")
    parent = "context.mizan"
    checks: list[str] = []
    for segment in segments:
        checks.append(f"{parent} has {segment}")
        parent = f"{parent}.{segment}"
    return " && ".join(checks)


def compile_condition(node: dict[str, Any]) -> str:
    if set(node) >= {"field", "op"}:
        field, operator = node["field"], node["op"]
        target = _path(field)
        presence = _present_expression(field)
        if operator == "present":
            return f"({presence})"
        if operator == "absent":
            return f"!({presence})"
        if "value" not in node:
            raise PolicyCompileError(f"operator {operator} requires value")
        value = node["value"]
        comparisons = {
            "eq": "==", "neq": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=",
        }
        if operator in comparisons:
            return f"(({presence}) && {target} {comparisons[operator]} {_literal(value)})"
        if operator in {"in", "not_in"}:
            if not isinstance(value, list):
                raise PolicyCompileError(f"operator {operator} requires an array")
            expression = f"{_literal(value)}.contains({target})"
            return f"(({presence}) && {'!' if operator == 'not_in' else ''}{expression})"
        if operator == "matches":
            if not isinstance(value, str):
                raise PolicyCompileError("matches requires a string pattern")
            # Cedar `like` is a glob language. Only `*` wildcards are admitted by the Mizan DSL.
            if any(character in value for character in "[]?\\"):
                raise PolicyCompileError("matches accepts literal text and '*' wildcards only")
            return f"(({presence}) && {target} like {_literal(value)})"
        raise PolicyCompileError(f"unsupported condition operator: {operator}")
    if set(node) == {"all"}:
        return "(" + " && ".join(compile_condition(item) for item in node["all"]) + ")"
    if set(node) == {"any"}:
        return "(" + " || ".join(compile_condition(item) for item in node["any"]) + ")"
    if set(node) == {"not"}:
        return f"!({compile_condition(node['not'])})"
    raise PolicyCompileError("condition must be a leaf or exactly one of all/any/not")


def _cedar_context(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _cedar_context(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_cedar_context(item) for item in value if item is not None]
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        return str(value)
    return value


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    match: PolicyMatch
    artifact: str
    policy_set: cedarpy.PolicySet

    def matches(self, context: EvaluationContext) -> bool:
        request = {
            "principal": {"type": "MizanPrincipal", "id": context.principal.id},
            "action": {"type": "MizanAction", "id": context.action.type},
            "resource": {"type": "MizanResource", "id": context.resource.id},
            "context": {"mizan": _cedar_context(context.model_dump(mode="json"))},
        }
        result = cedarpy.is_authorized(request, self.policy_set, [])
        if result.diagnostics.errors:
            raise RuntimeError(f"Cedar evaluation error: {result.diagnostics.errors}")
        return result.decision == cedarpy.Decision.Allow


@lru_cache(maxsize=4096)
def compile_policy(document_json: str) -> CompiledPolicy:
    document = json.loads(document_json)
    if document.get("status") != "ACTIVE":
        raise PolicyCompileError("only ACTIVE policies may enter the evaluator cache")
    condition = compile_condition(document["conditions"])
    policy_name = f"{document['policy_id']}_v{document['version']}"
    artifact = (
        f'@id("{policy_name}")\n'
        "permit(principal, action, resource)\n"
        f"when {{ {condition} }};"
    )
    try:
        policy_set = cedarpy.PolicySet.from_str(artifact)
    except ValueError as exc:
        raise PolicyCompileError(f"Cedar rejected compiled policy: {exc}") from exc
    match = PolicyMatch(
        policy_id=document["policy_id"], version=document["version"],
        content_hash=document["content_hash"], decision=document["decision"],
        priority=document["priority"], constraints=document.get("constraints"),
    )
    return CompiledPolicy(match=match, artifact=artifact, policy_set=policy_set)


class CedarPolicyEvaluator:
    @staticmethod
    def _applies(document: dict[str, Any], context: EvaluationContext) -> bool:
        selectors = document.get("applies_to", {})
        values: dict[str, Any] = {
            "agent_ids": context.agent.id,
            "tool_ids": context.tool.id,
            "intents": context.intent,
            "action_types": context.action.type,
            "environments": context.environment.get("name"),
            "risk_levels": context.security.get("risk_level"),
        }
        return all(values[key] in allowed for key, allowed in selectors.items())

    def evaluate(self, documents: list[dict[str, Any]], context: EvaluationContext) -> list[PolicyMatch]:
        matches: list[PolicyMatch] = []
        for document in documents:
            if not self._applies(document, context):
                continue
            canonical_source = json.dumps(document, sort_keys=True, separators=(",", ":"))
            compiled = compile_policy(canonical_source)
            if compiled.matches(context):
                matches.append(compiled.match)
        return matches
