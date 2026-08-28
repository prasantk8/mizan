"""`mizan-mcp-gateway` — put any MCP tool server behind a governance control plane.

    [mizan]
    url = "https://mizan.internal"
    agent_id = "agt_wealth-advisor"
    agent_token = "..."          # or MIZAN_AGENT_TOKEN

    [upstream]
    command = "npx"
    args = ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

Point the MCP client at this process instead of the tool server. Nothing else changes.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import anyio
import mcp.server.stdio
from mizan import MizanClient

from .config import ConfigurationError, GatewayConfig, load
from .governance import ToolGovernor
from .registration import RegistrySync
from .server import build_server
from .transport import http_client
from .upstream import UpstreamServer


async def serve(config: GatewayConfig) -> None:
    upstream = UpstreamServer(config)
    await upstream.connect()
    client = MizanClient(
        config.mizan_url,
        config.agent_token,
        agent_id=config.agent_id,
        agent_version=config.agent_version,
        environment=config.environment,
        transport=http_client(config),
    )
    try:
        if config.register_unknown_tools:
            await _register(config, upstream)
        governor = ToolGovernor(config, client)
        server = build_server(config, upstream, governor)
        async with mcp.server.stdio.stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        client.close()
        await upstream.aclose()


async def _register(config: GatewayConfig, upstream: UpstreamServer) -> None:
    tools = [tool.model_dump(by_alias=True) for tool in await upstream.list_tools()]
    tenant_id = _tenant_from_token(config.agent_token)
    sync = RegistrySync(config)
    try:
        await anyio.to_thread.run_sync(lambda: sync.ensure(tools, tenant_id))
    finally:
        sync.close()
    logging.getLogger("mizan.mcp.gateway").info(
        "registered %d tools, %d already governed", len(sync.registered), len(sync.skipped)
    )


def _tenant_from_token(token: str) -> str:
    """The tenant is read from the token, never configured — I-3, on the client side too."""
    import base64
    import json

    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["tenant_id"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Govern an MCP tool server with Mizan")
    parser.add_argument("--config", type=Path, help="TOML configuration file")
    parser.add_argument("--log-level", default="warning")
    arguments = parser.parse_args(argv)
    # stderr only: stdout is the MCP transport, and a stray log line corrupts the protocol.
    logging.basicConfig(level=arguments.log_level.upper(), stream=sys.stderr)
    try:
        config = load(arguments.config)
    except (ConfigurationError, OSError, ValueError) as exc:
        print(f"mizan-mcp-gateway refused to start: {exc}", file=sys.stderr)
        return 78  # EX_CONFIG
    anyio.run(serve, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
