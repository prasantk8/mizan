"""The upstream MCP server, held open for the life of the gateway."""

from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Any

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import GatewayConfig


class UpstreamServer:
    """A thin, honest wrapper: it forwards and it does not interpret."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self._stack = AsyncExitStack()
        self._session: ClientSession | None = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("upstream MCP server is not connected")
        return self._session

    async def connect(self) -> None:
        parameters = StdioServerParameters(
            command=self.config.upstream_command,
            args=list(self.config.upstream_args),
            env=dict(self.config.upstream_env) or None,
        )
        read, write = await self._stack.enter_async_context(stdio_client(parameters))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()

    async def aclose(self) -> None:
        self._session = None
        await self._stack.aclose()

    async def list_tools(self) -> list[types.Tool]:
        return (await self.session.list_tools()).tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return await self.session.call_tool(name, arguments)
