#!/usr/bin/env python3
"""A minimal upstream MCP server for the gateway tests.

It writes a line to `MIZAN_TEST_TOOL_LOG` every time a tool actually runs, which is how the tests
tell "refused" apart from "ran and then was reported as refused".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import anyio
import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import Server

TOOLS = [
    types.Tool(
        name="read_portfolio",
        description="Read a customer portfolio",
        inputSchema={
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
            "required": ["customer_id"],
        },
    ),
    types.Tool(
        name="rebalance_portfolio",
        description="Move money between holdings to reach the target allocation",
        inputSchema={
            "type": "object",
            "properties": {"customer_id": {"type": "string"}, "amount": {"type": "integer"}},
            "required": ["customer_id", "amount"],
        },
    ),
]


def _record(name: str) -> None:
    path = os.environ.get("MIZAN_TEST_TOOL_LOG")
    if path:
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(name + "\n")


async def on_list_tools(
    _context: Any, _params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    return types.ListToolsResult(tools=TOOLS)


async def on_call_tool(_context: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    _record(params.name)
    arguments = params.arguments or {}
    if params.name == "read_portfolio":
        text = f"portfolio for {arguments.get('customer_id')}: 3 holdings"
    else:
        text = f"rebalanced {arguments.get('amount')} for {arguments.get('customer_id')}"
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])


async def main() -> None:
    server = Server(
        "echo-tools", version="0.1.0", on_list_tools=on_list_tools, on_call_tool=on_call_tool
    )
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
