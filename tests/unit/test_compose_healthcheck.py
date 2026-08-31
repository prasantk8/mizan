"""The PostgreSQL healthcheck must prove the real server is listening.

`postgres-contract` went red on a tree whose only changes were JavaScript and
markdown, 125 milliseconds after the container reported healthy::

    21:40:58.318  Container mizan-schema-test-postgres-1  Healthy
    21:40:58.443  psql: error: connection to server on socket
                  "/var/run/postgresql/.s.PGSQL.5432" failed:
                  No such file or directory

That is the documented postgres entrypoint sequence, not a mystery. While
`/docker-entrypoint-initdb.d` runs -- and this repository mounts its migrations
there, so it always runs and is not brief -- the entrypoint starts a *temporary*
server that listens on the unix socket only, then stops it and restarts on TCP.
A socket-local ``pg_isready`` answers "ready" against that temporary server, so
compose can mark the container healthy inside the window where the real server
is down.

A gate that fails for a reason unrelated to the change under test does not
merely cost a rerun: it teaches everyone to disbelieve red, which is the whole
value H-8 assigns to CI.
"""

from __future__ import annotations

import re
from pathlib import Path

COMPOSE_FILES = ["compose.yaml", "compose.test.yaml"]
# Only the declared command counts. An earlier version of this regex also
# matched the word "pg_isready" inside the explanatory comment above the
# healthcheck and failed on it, which is a test finding the wrong thing.
HEALTHCHECK = re.compile(r"test:\s*\[[^\]]*pg_isready[^\]]*\]")


def _healthchecks() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for name in COMPOSE_FILES:
        path = Path(name)
        if not path.exists():
            continue
        for match in HEALTHCHECK.finditer(path.read_text()):
            found.append((name, match.group(0)))
    return found


def test_every_postgres_healthcheck_requires_a_tcp_connection() -> None:
    checks = _healthchecks()
    assert checks, "expected at least one pg_isready healthcheck to guard"

    socket_only = [
        (name, command)
        for name, command in checks
        if not re.search(r"-h\s|--host", command)
    ]
    assert not socket_only, (
        "these healthchecks can be satisfied by the entrypoint's temporary "
        "socket-only server, so the container can report healthy while the real "
        f"server is still restarting: {socket_only}"
    )


def test_healthcheck_retries_survive_migration_initialisation() -> None:
    checks = _healthchecks()
    assert checks, "expected at least one pg_isready healthcheck to guard"

    # The TCP check is the fix, but it also means the container stays unhealthy
    # for the whole init phase rather than briefly lying. The budget has to cover
    # running every migration. Overlay files that declare no healthcheck add
    # nothing to this contract and are not represented as a passing skip.
    for name, _command in checks:
        text = Path(name).read_text()
        interval = int(re.search(r"interval:\s*(\d+)s", text).group(1))
        retries = int(re.search(r"retries:\s*(\d+)", text).group(1))
        assert interval * retries >= 30, (
            f"{name} allows only {interval * retries}s for PostgreSQL to initialise "
            "and run every migration before the container is declared unhealthy"
        )
