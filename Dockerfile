# syntax=docker/dockerfile:1.7

FROM ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded AS uv
FROM python:3.12-slim-trixie@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17 AS builder

COPY --from=uv /uv /uvx /bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
COPY control-plane ./control-plane
COPY integrations ./integrations
COPY security ./security
COPY sdk ./sdk
RUN uv sync --frozen --no-dev

FROM python:3.12-slim-trixie@sha256:7a8b475003c4fe15a2cd4e55e5cfc2f3560bdc9333d624f24cdd6d4340fd7a17 AS runtime

RUN apt-get update \
    && apt-get upgrade --yes \
    && apt-get install --no-install-recommends --yes ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 mizan \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /app --shell /usr/sbin/nologin mizan

WORKDIR /app
COPY --from=builder --chown=65532:65532 /app/.venv ./.venv
COPY --from=builder --chown=65532:65532 /app/control-plane ./control-plane
COPY --from=builder --chown=65532:65532 /app/integrations ./integrations
COPY --from=builder --chown=65532:65532 /app/security ./security
COPY --from=builder --chown=65532:65532 /app/sdk ./sdk
COPY --chown=65532:65532 ui ./ui
COPY --chown=65532:65532 SPEC_v1.md ./SPEC_v1.md
COPY --chown=65532:65532 scripts/migrate.py ./scripts/migrate.py
COPY --chown=65532:65532 infra/postgres/migrations ./infra/postgres/migrations
RUN mkdir -p /app/var/evidence && chown 65532:65532 /app/var/evidence

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    MIZAN_EVIDENCE_OBJECT_STORE_ROOT=/app/var/evidence
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=4 \
  CMD python -c 'import os,ssl,urllib.request; tls=bool(os.getenv("MIZAN_TLS_CERTIFICATE_FILE")); ctx=ssl.create_default_context(cafile=os.getenv("MIZAN_HEALTH_SERVER_CA_FILE")) if tls else None; ctx.load_cert_chain(os.environ["MIZAN_HEALTH_CLIENT_CERTIFICATE_FILE"],os.environ["MIZAN_HEALTH_CLIENT_PRIVATE_KEY_FILE"]) if ctx else None; urllib.request.urlopen(("https" if tls else "http")+"://127.0.0.1:"+os.getenv("MIZAN_HTTP_PORT","8080")+"/health/ready",context=ctx,timeout=4).read()'
ENTRYPOINT ["mizan-control-plane"]
