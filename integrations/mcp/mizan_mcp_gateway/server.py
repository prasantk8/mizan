"""The MCP server a client points at instead of the tool server.

`tools/list` passes through unchanged: a governed tool is the same tool, and rewriting the
descriptions would change what the model is being asked to reason about.

`tools/call` is the whole product. Nothing reaches the upstream server until the control plane has
recorded a decision permitting it, and nothing that reaches it goes unrecorded.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anyio.to_thread
import mcp.types as types
from mcp.server.lowlevel import Server

from .config import GatewayConfig
from .governance import Permission, Refusal, ToolGovernor
from .upstream import UpstreamServer

LOGGER = logging.getLogger("mizan.mcp.gateway")


def refusal_result(refusal: Refusal) -> types.CallToolResult:
    """A refusal the model can act on: what happened, and what it means for the user.

    `isError` is true because the call did not happen. The text names the reason class so the
    model can tell "policy said no" apart from "a person has not answered yet", which are
    different things to say to a user.
    """
    reference = f" (decision {refusal.decision_id})" if refusal.decision_id else ""
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=f"{refusal.message}{reference}")],
        structuredContent={
            "mizan": {
                "outcome": "refused",
                "reason_class": refusal.reason_class,
                "decision_id": refusal.decision_id,
                "approval_id": refusal.approval_id,
            }
        },
        isError=True,
    )


def governed_result(result: types.CallToolResult, permission: Permission) -> types.CallToolResult:
    """The upstream result, with the evidence reference attached and nothing else changed."""
    existing = result.structured_content if isinstance(result.structured_content, dict) else None
    annotated = dict(existing or {})
    annotated["mizan"] = {
        "outcome": "allowed",
        "decision_id": permission.decision.decision_id,
        "decision": permission.decision.decision,
        "risk": permission.decision.risk.get("level"),
        "lease_id": (permission.lease or {}).get("lease_id"),
    }
    return types.CallToolResult(
        content=result.content,
        structuredContent=annotated,
        isError=result.is_error,
    )


class GatewayHandlers:
    """The two MCP methods that matter, with no JSON-RPC plumbing around them."""

    def __init__(
        self, config: GatewayConfig, upstream: UpstreamServer, governor: ToolGovernor
    ) -> None:
        self.config = config
        self.upstream = upstream
        self.governor = governor

    async def list_tools(self) -> types.ListToolsResult:
        """Pass through unchanged: a governed tool is the same tool."""
        return types.ListToolsResult(tools=await self.upstream.list_tools())

    async def call_tool(self, params: types.CallToolRequestParams) -> types.CallToolResult:
        arguments = dict(params.arguments or {})
        intent = _intent(params, arguments)
        proof_token = _proof_token(params)
        memtara_chain_head = _memtara_chain_head(params)
        verdict = await anyio.to_thread.run_sync(
            lambda: self.governor.authorize(
                params.name,
                arguments,
                intent=intent,
                proof_token=proof_token,
                memtara_chain_head=memtara_chain_head,
            )
        )
        if isinstance(verdict, Refusal):
            LOGGER.info("refused %s: %s", params.name, verdict.reason_class)
            return refusal_result(verdict)
        try:
            result = await self.upstream.call_tool(params.name, arguments)
        except Exception as failure:
            # The lease is closed with the failure class before the error propagates: an
            # execution that started and did not finish must not look like one that never began.
            failure_class = type(failure).__name__
            await anyio.to_thread.run_sync(
                lambda: self.governor.record_outcome(
                    verdict, {"error": failure_class}, "tool_error"
                )
            )
            raise
        await anyio.to_thread.run_sync(
            lambda: self.governor.record_outcome(verdict, _hashable(result))
        )
        return governed_result(result, verdict)


def build_server(
    config: GatewayConfig, upstream: UpstreamServer, governor: ToolGovernor
) -> Server[Any]:
    handlers = GatewayHandlers(config, upstream, governor)

    async def on_list_tools(
        _context: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return await handlers.list_tools()

    async def on_call_tool(
        _context: Any, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        return await handlers.call_tool(params)

    return Server(
        config.server_name,
        version="0.1.0",
        instructions=(
            "Every tool call is authorized by a Mizan control plane before it runs. A call may be "
            "refused by policy, or paused until a human approves it; the tool result says which."
        ),
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )


def _intent(params: types.CallToolRequestParams, arguments: dict[str, Any]) -> str:
    """What the client says it is doing. Declared, never inferred — and recorded as declared."""
    meta = params.meta or {}
    stated = meta.get("mizan/intent") if isinstance(meta, dict) else None
    if isinstance(stated, str) and stated.strip():
        return stated.strip()[:120]
    return f"MCP tools/call {params.name}"[:120]


def _proof_token(params: types.CallToolRequestParams) -> str | None:
    """Carry the MCP client's proof metadata without reading or interpreting the token."""
    meta = params.meta or {}
    token = meta.get("x-memtara-proof") if isinstance(meta, dict) else None
    return token if isinstance(token, str) else None


def _memtara_chain_head(params: types.CallToolRequestParams) -> str | None:
    """Carry the MCP client's chain-head metadata without reading or interpreting it."""
    meta = params.meta or {}
    chain_head = meta.get("x-memtara-chain-head") if isinstance(meta, dict) else None
    return chain_head if isinstance(chain_head, str) else None


def _hashable(result: types.CallToolResult) -> Any:
    """What the evidence commits to: the shape of the result, never a payload."""
    try:
        return json.loads(result.model_dump_json())
    except (TypeError, ValueError):
        return {"content_blocks": len(result.content), "is_error": result.is_error}
