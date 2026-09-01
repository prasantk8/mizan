"""`mizan-control-plane` — the process that serves the API."""

from __future__ import annotations

import argparse
import logging
import sys

import uvicorn

from .config import Settings
from .observability import configure_logging
from .runtime import (
    StartupRefused,
    build_runtime,
    spiffe_scope_protocol_class,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Mizan control plane API")
    parser.add_argument("--host", help="overrides MIZAN_HTTP_HOST")
    parser.add_argument("--port", type=int, help="overrides MIZAN_HTTP_PORT")
    parser.add_argument("--log-level", help="overrides MIZAN_LOG_LEVEL")
    arguments = parser.parse_args(argv)
    # Was `logging.basicConfig(level=...)`, whose default formatter renders `%(message)s` and
    # discards everything a call site attaches through `extra=`. The two places this system
    # reports a security-relevant failure both pass their tenant and decision that way, so the
    # operator investigating one got a line naming neither (T-107). Structured from the first
    # line, too: a startup refusal is exactly the log an operator greps, and `build_runtime`
    # reconfigures with the settings' level once it can read them.
    configure_logging(arguments.log_level or "info")
    try:
        settings = Settings.from_environment(require_workforce_oidc=True)
        runtime = build_runtime(settings)
    except (StartupRefused, RuntimeError) as exc:
        print(f"mizan-control-plane refused to start: {exc}", file=sys.stderr)
        return 78  # EX_CONFIG
    if settings.environment != "production" and not settings.mutual_tls_configured:
        logging.getLogger(__name__).warning(
            "no client CA configured: execution endpoints will answer 401 because no peer SPIFFE "
            "identity can be verified. Set MIZAN_TLS_* to exercise the execution path."
        )
    uvicorn.run(
        runtime.app,
        host=arguments.host or settings.http_host,
        port=arguments.port or settings.http_port,
        log_level=(arguments.log_level or settings.log_level).lower(),
        http=spiffe_scope_protocol_class(),
        # uvicorn otherwise installs its own dictConfig and its own access log, which produces a
        # process emitting two log formats at once and one access line per request in each. The
        # duplicate is the worse half: uvicorn's line has the request path rather than the route
        # template, and knows nothing of the trace, tenant or decision the request belonged to.
        log_config=None,
        access_log=False,
        **_tls_arguments(settings),
    )
    return 0


def _tls_arguments(settings: Settings) -> dict[str, object]:
    if not settings.mutual_tls_configured:
        return {}
    return {
        "ssl_certfile": settings.tls_certificate_file,
        "ssl_keyfile": settings.tls_private_key_file,
        "ssl_ca_certs": settings.tls_client_ca_file,
        "ssl_cert_reqs": 2,  # ssl.CERT_REQUIRED
    }


if __name__ == "__main__":
    raise SystemExit(main())
