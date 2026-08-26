"""Adapters for the two tool-use wire formats agents actually emit.

Neither adapter imports an vendor SDK: they take the tool-call payload those APIs already hand
you, so the same router works with the Anthropic Messages API, the OpenAI chat completions API, a
LangChain tool, or a hand-rolled loop.

A refusal is returned to the model as a tool result, not raised. The model needs to read what
happened and say so to the user; an exception up the stack turns a governed refusal into a crash.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .client import Decision, MizanClient, Principal, Resource
from .decorator import result_hash
from .errors import ApprovalRejected, ApprovalTimeout, Denied, ProblemError


@dataclass(frozen=True, slots=True)
class GovernedTool:
    tool_id: str
    action_type: str
    resource: Resource
    handler: Callable[..., Any]
    intent: str | None = None


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    name: str
    call_id: str
    ok: bool
    content: Any
    decision: Decision | None = None
    refusal_class: str | None = None


class GovernedToolRouter:
    """Runs a model's tool calls through Mizan before running them at all."""

    def __init__(
        self,
        client: MizanClient,
        tools: dict[str, GovernedTool],
        *,
        principal: Principal,
        approval_timeout_seconds: float = 900.0,
        on_pending: Callable[[Decision], None] | None = None,
    ) -> None:
        self.client = client
        self.tools = tools
        self.principal = principal
        self.approval_timeout_seconds = approval_timeout_seconds
        self.on_pending = on_pending

    def invoke(self, name: str, call_id: str, arguments: dict[str, Any]) -> ToolOutcome:
        tool = self.tools.get(name)
        if tool is None:
            return ToolOutcome(name, call_id, False, f"Unknown tool {name!r}.", None, "unknown_tool")
        try:
            decision = self.client.decide(
                tool_id=tool.tool_id,
                arguments=arguments,
                action_type=tool.action_type,
                intent=tool.intent or f"call {name}",
                principal=self.principal,
                resource=tool.resource,
                approval_timeout_seconds=self.approval_timeout_seconds,
                on_pending=self.on_pending,
            )
        except Denied as denied:
            return ToolOutcome(
                name,
                call_id,
                False,
                f"Refused by policy ({denied.decision_id}): {'; '.join(denied.reasons)}",
                None,
                "denied",
            )
        except ApprovalRejected as rejected:
            return ToolOutcome(
                name,
                call_id,
                False,
                f"An approver declined this action ({rejected.state}).",
                None,
                "approval_rejected",
            )
        except ApprovalTimeout:
            return ToolOutcome(
                name,
                call_id,
                False,
                "This action is still waiting for an approver and has not been performed.",
                None,
                "approval_pending",
            )
        except ProblemError as problem:
            return ToolOutcome(
                name, call_id, False, f"Authorization failed: {problem.detail}", None, problem.code
            )
        value = tool.handler(**arguments)
        return ToolOutcome(name, call_id, True, value, decision)

    # --- Anthropic Messages API -------------------------------------------------------------
    def anthropic_tool_result(self, block: dict[str, Any]) -> dict[str, Any]:
        outcome = self.invoke(block["name"], block["id"], dict(block.get("input") or {}))
        return {
            "type": "tool_result",
            "tool_use_id": outcome.call_id,
            "is_error": not outcome.ok,
            "content": outcome.content
            if isinstance(outcome.content, str)
            else json.dumps(outcome.content, default=str),
        }

    def anthropic_tool_results(self, content: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            self.anthropic_tool_result(block)
            for block in content
            if block.get("type") == "tool_use"
        ]

    # --- OpenAI chat completions ------------------------------------------------------------
    def openai_tool_message(self, call: dict[str, Any]) -> dict[str, Any]:
        function = call["function"]
        arguments = function.get("arguments") or "{}"
        parsed = json.loads(arguments) if isinstance(arguments, str) else dict(arguments)
        outcome = self.invoke(function["name"], call["id"], parsed)
        return {
            "role": "tool",
            "tool_call_id": outcome.call_id,
            "content": outcome.content
            if isinstance(outcome.content, str)
            else json.dumps(outcome.content, default=str),
        }

    def openai_tool_messages(self, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.openai_tool_message(call) for call in calls]

    # --- LangChain --------------------------------------------------------------------------
    def langchain_tools(self) -> list[Any]:
        """`StructuredTool`s that route through Mizan. Requires langchain-core at call time."""
        from langchain_core.tools import StructuredTool  # noqa: PLC0415

        def build(name: str, tool: GovernedTool) -> Any:
            def run(**arguments: Any) -> Any:
                outcome = self.invoke(name, f"lc_{name}", arguments)
                if not outcome.ok:
                    raise RuntimeError(outcome.content)
                return outcome.content

            return StructuredTool.from_function(
                func=run, name=name, description=tool.intent or f"Governed {tool.tool_id}"
            )

        return [build(name, tool) for name, tool in self.tools.items()]


__all__ = ["GovernedTool", "GovernedToolRouter", "ToolOutcome", "result_hash"]
