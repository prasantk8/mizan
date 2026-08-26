"""Mizan Python SDK.

    from mizan import MizanClient, Principal, Resource

    with MizanClient() as mizan:
        decision = mizan.decide(
            tool_id="tool_portfolio-rebalance",
            arguments={"customer_id": "cus_42", "amount": 250_000},
            action_type="financial_write",
            intent="rebalance to the target allocation",
            principal=Principal(id="prn_alice-01", role="advisor"),
            resource=Resource("portfolio/42", "portfolio", "core-banking", "financial"),
        )

`decide` raises `Denied` when policy refuses, and blocks while humans decide when policy requires
an approval. It never returns an allow the control plane did not give.
"""

from .binding import UnclassifiedArgument, parameters_hash, read_pointer
from .client import Decision, MizanClient, Principal, Resource, rfc3339_now, uuid7
from .decorator import govern, result_hash
from .errors import (
    ApprovalRejected,
    ApprovalTimeout,
    Denied,
    MizanError,
    NotImplementedDecision,
    ProblemError,
)

__all__ = [
    "ApprovalRejected",
    "ApprovalTimeout",
    "Decision",
    "Denied",
    "MizanClient",
    "MizanError",
    "NotImplementedDecision",
    "Principal",
    "ProblemError",
    "Resource",
    "UnclassifiedArgument",
    "govern",
    "parameters_hash",
    "read_pointer",
    "result_hash",
    "rfc3339_now",
    "uuid7",
]
__version__ = "0.1.0"
