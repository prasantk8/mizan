"""A bound on how much an unauthenticated stranger can make this process allocate.

Every write route reads its body before anything authenticates the caller: FastAPI parses and
validates the JSON to build the request model, and the dependency that verifies the bearer token
runs after that. So the size of a request body was, until now, entirely the client's choice --
`MIZAN_MAX_REQUEST_BODY_BYTES` did not exist and nothing else capped it. A hundred-megabyte body
was parsed in full and *then* refused 401.

The cap is applied at the ASGI layer for that reason. A check inside a route handler runs after
the allocation it is meant to prevent, which is not a cap; it is a report.

Two paths, because a client can decline to be honest about its own size:

  * a `Content-Length` larger than the limit is refused before the body is read at all;
  * a body that arrives in chunks is counted as it arrives and refused the moment it crosses the
    limit, which is what a chunked request without `Content-Length` does.

`413` is the answer in both cases, as a `problem+json` document like every other refusal here --
a client that gets a bare status from one middleware and a structured problem from every route
has to handle two error formats to talk to one service.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Registry documents are the largest legitimate body: an Agent or Tool with its binding profile.
# The largest fixture in this repository is under 4 KiB, so a mebibyte is three orders of
# magnitude of headroom rather than a number tuned against real traffic. T-116 owns measuring it.
DEFAULT_MAX_REQUEST_BODY_BYTES = 1024 * 1024


class RequestBodyLimitMiddleware:
    """Refuse a request body larger than `limit` bytes before it is fully read."""

    def __init__(self, app: ASGIApp, limit: int = DEFAULT_MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        declared = _content_length(scope)
        if declared is not None and declared > self.limit:
            return await self._refuse(scope, send, declared)

        received = 0
        too_large = False

        async def counted_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.limit:
                    too_large = True
                    # Stop the body here. The application sees a truncated request and the
                    # refusal below is what the client is actually told.
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            if too_large:
                return
            await send(message)

        await self.app(scope, counted_receive, guarded_send)
        if too_large:
            await self._refuse(scope, send, received)

    async def _refuse(self, scope: Scope, send: Send, size: int) -> None:
        body = json.dumps(
            {
                "type": "https://mizan.ai/problems/request_body_too_large",
                "title": "Request Body Too Large",
                "status": 413,
                "detail": (
                    f"Request body of {size} bytes exceeds the {self.limit} byte limit"
                ),
                "instance": scope.get("path", "/"),
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/problem+json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                # A malformed Content-Length is not a size we can trust; fall through to
                # counting the body as it arrives rather than believing the header.
                return None
    return None
