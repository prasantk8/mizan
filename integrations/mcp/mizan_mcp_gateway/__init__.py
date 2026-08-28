"""Mizan MCP Governance Gateway.

Wraps any MCP tool server so that every `tools/call` is authorized, recorded, and — where policy
says so — paused until a human approves it. The gateway never decides: it asks, forwards what it
is permitted to forward, and refuses everything else in words the model can repeat.
"""

from .config import ConfigurationError, GatewayConfig, ToolDeclaration, load
from .governance import Permission, Refusal, ToolGovernor
from .registration import RegistrySync, tool_document
from .server import GatewayHandlers, build_server, governed_result, refusal_result
from .upstream import UpstreamServer

__all__ = [
    "ConfigurationError",
    "GatewayConfig",
    "GatewayHandlers",
    "Permission",
    "RegistrySync",
    "Refusal",
    "ToolDeclaration",
    "ToolGovernor",
    "UpstreamServer",
    "build_server",
    "governed_result",
    "load",
    "refusal_result",
    "tool_document",
]
__version__ = "0.1.0"
