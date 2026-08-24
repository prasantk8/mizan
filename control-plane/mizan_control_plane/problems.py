from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class Problem(Exception):
    def __init__(self, status: int, code: str, detail: str) -> None:
        self.status = status
        self.code = code
        self.detail = detail
        super().__init__(detail)


def problem_response(request: Request, exc: Problem) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status,
        media_type="application/problem+json",
        content={
            "type": f"https://mizan.ai/problems/{exc.code}",
            "title": exc.code.replace("_", " ").title(),
            "status": exc.status,
            "detail": exc.detail,
            "instance": str(request.url.path),
        },
    )

