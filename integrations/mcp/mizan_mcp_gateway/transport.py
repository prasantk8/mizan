"""How the gateway reaches the control plane.

A production control plane speaks TLS and asks for a client certificate; redeeming an execution
token *requires* one, because the authorized executor is read off the verified peer certificate
(ADR-001 Amendment B) and never off the request body. So the gateway's own workload identity is
transport configuration, not a header — and configuring an executor identity without a client
certificate is a configuration error, not a runtime surprise on the first HIGH-risk call.
"""

from __future__ import annotations

import ssl

import httpx

from .config import GatewayConfig


def tls_context(config: GatewayConfig) -> ssl.SSLContext | bool:
    if not config.mizan_url.lower().startswith("https"):
        return True
    context = ssl.create_default_context(cafile=config.ca_file or None)
    if config.client_certificate_file:
        context.load_cert_chain(config.client_certificate_file, config.client_key_file)
    return context


def http_client(config: GatewayConfig, timeout: float = 15.0) -> httpx.Client:
    """A transport, with no credential on it: callers set their own Authorization header."""
    return httpx.Client(base_url=config.mizan_url, verify=tls_context(config), timeout=timeout)
