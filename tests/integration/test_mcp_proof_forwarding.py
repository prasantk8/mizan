"""T-136 integration: MCP metadata reaches the Mizan authorization boundary unchanged."""

from __future__ import annotations

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.shared.message import SessionMessage
from mizan_mcp_gateway import build_server

from tests.unit.test_mcp_gateway import ARGUMENTS, FakeControlPlane, FakeUpstream, handlers


def test_a_real_mcp_session_preserves_memtara_metadata_through_the_gateway() -> None:
    """Exercise protocol serialization, the SDK header, and the allow/deny forwarding paths."""
    opaque_token = "opaque-over-the-mcp-session"
    opaque_chain_head = "chain-head-over-the-mcp-session"
    plane = FakeControlPlane(proof_decisions={opaque_token: "ALLOW", None: "DENY"})
    upstream = FakeUpstream()
    handler = handlers(plane, upstream)
    server = build_server(handler.config, upstream, handler.governor)

    async def drive() -> tuple[types.CallToolResult, types.CallToolResult]:
        client_write, server_read = anyio.create_memory_object_stream[SessionMessage](0)
        server_write, client_read = anyio.create_memory_object_stream[SessionMessage](0)
        async with (
            client_write,
            server_read,
            server_write,
            client_read,
            anyio.create_task_group() as tasks,
        ):
            tasks.start_soon(
                server.run,
                server_read,
                server_write,
                server.create_initialization_options(),
            )
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()
                await session.list_tools()
                allowed = await session.call_tool(
                    "write_file",
                    ARGUMENTS,
                    meta={
                        "x-memtara-proof": opaque_token,
                        "x-memtara-chain-head": opaque_chain_head,
                    },
                )
                refused = await session.call_tool("write_file", ARGUMENTS)
            tasks.cancel_scope.cancel()
        assert isinstance(allowed, types.CallToolResult)
        assert isinstance(refused, types.CallToolResult)
        return allowed, refused

    allowed, refused = anyio.run(drive)
    assert allowed.is_error is False
    assert refused.is_error is True
    assert plane.proof_headers == [opaque_token, None]
    assert plane.chain_head_headers == [opaque_chain_head, None]
    assert upstream.calls == [("write_file", ARGUMENTS)]
