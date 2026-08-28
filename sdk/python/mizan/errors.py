"""What the control plane can say that is not "yes"."""

from __future__ import annotations

from typing import Any


class MizanError(Exception):
    """Base class, so a caller can catch everything Mizan raises and nothing else."""


class ProblemError(MizanError):
    """An RFC 9457 problem document came back."""

    def __init__(self, status: int, code: str, detail: str, document: dict[str, Any]) -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail
        self.document = document


class Denied(MizanError):
    """Policy said no. `reasons` are the recorded reasons, not a guess at them."""

    def __init__(self, decision_id: str, reasons: list[str]) -> None:
        super().__init__(f"{decision_id} denied: {'; '.join(reasons)}")
        self.decision_id = decision_id
        self.reasons = reasons


class ApprovalRejected(MizanError):
    def __init__(self, decision_id: str, approval_id: str, state: str) -> None:
        super().__init__(f"{decision_id} approval {approval_id} ended {state}")
        self.decision_id = decision_id
        self.approval_id = approval_id
        self.state = state


class ApprovalTimeout(MizanError):
    """The caller stopped waiting. The approval is still open; nothing was cancelled."""

    def __init__(self, decision_id: str, approval_id: str, waited_seconds: float) -> None:
        super().__init__(
            f"{decision_id} approval {approval_id} still open after {waited_seconds:.0f}s"
        )
        self.decision_id = decision_id
        self.approval_id = approval_id
        self.waited_seconds = waited_seconds


class NotImplementedDecision(MizanError):
    """The winning policy asked for an outcome v1 does not implement (501)."""
