"""SPEC §2 says `ADR_Record.trace_id` is a W3C traceparent trace-id. Now it is one.

This is a *contract* test, not a feature test. Until T-073 the field was populated with
`sha256(request_id)[:32]`: thirty-two hex characters, stable across retries of the same request,
schema-valid, and a member of no trace that has ever existed. Every property an automated check
looks at was satisfied, which is why nothing caught it for the whole life of the tree. What it
cost is only visible from the other end — an investigator holding a signed ADR_Record, trying to
open the request that produced it, finding a trace id their tracing backend has never seen, and
having nothing in the record to tell them the id was never real.

`test_the_trace_id_recorded_is_the_callers_trace_and_not_a_hash_of_the_request_id` fails on
793a54a on its second assertion — the recorded id there *is* the digest.
"""

from __future__ import annotations

import hashlib

from mizan_control_plane.observability import TraceContext, context

from tests.unit.test_authorization import context as evaluation_context
from tests.unit.test_authorization import identity, service

CALLER = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
CALLER_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def _legacy_trace_id(request_id: str) -> str:
    """Exactly what `service.py` wrote before T-073, kept here so the test can reject it."""
    return hashlib.sha256(str(request_id).encode()).hexdigest()[:32]


def test_the_trace_id_recorded_is_the_callers_trace_and_not_a_hash_of_the_request_id() -> None:
    subject, repository = service()
    request = evaluation_context()
    caller = TraceContext.parse(CALLER)
    assert caller is not None

    with context(trace_id=caller.trace_id, span_id=caller.span_id):
        subject.authorize(identity(), request)

    record = repository.adr_documents[0]
    assert record["trace_id"] == CALLER_TRACE
    # Rule 9: the guarantee is demonstrated by rejecting the value the old code produced.
    assert record["trace_id"] != _legacy_trace_id(request.request_id)


def test_the_recorded_span_is_the_span_that_decided_rather_than_null() -> None:
    """`span_id` was hardcoded `None`, so a record named a trace with no position inside it.

    A trace id alone puts the decision somewhere in a request that may have fanned out to a dozen
    services. The span is what says *this* is where the authorization happened.
    """
    subject, repository = service()
    caller = TraceContext.parse(CALLER)
    assert caller is not None
    with context(trace_id=caller.trace_id, span_id=caller.span_id):
        subject.authorize(identity(), evaluation_context())
    record = repository.adr_documents[0]
    assert record["span_id"] == "00f067aa0ba902b7"
    assert len(record["span_id"]) == 16


def test_a_decision_made_with_no_ambient_trace_still_names_a_real_one() -> None:
    """A trace id is minted, never derived from something that is not a trace.

    A background caller has no inbound `traceparent`. The old code would have produced a digest
    that looks joinable and is not; the new code starts a trace, which is honest — the record names
    an id that identifies this decision and nothing else claims otherwise.
    """
    subject, repository = service()
    request = evaluation_context()
    subject.authorize(identity(), request)
    record = repository.adr_documents[0]
    assert len(record["trace_id"]) == 32 and int(record["trace_id"], 16) != 0
    assert record["trace_id"] != _legacy_trace_id(request.request_id)
    assert record["span_id"] is not None


def test_two_decisions_in_one_trace_share_it_and_two_traces_do_not() -> None:
    """A trace groups a request's decisions; a request id identifies exactly one."""
    subject, repository = service()
    with context(trace_id=CALLER_TRACE, span_id="00f067aa0ba902b7"):
        subject.authorize(identity(), evaluation_context())
        subject.authorize(
            identity(), evaluation_context("018f47a6-7b42-7c00-8000-0000000000a2")
        )
    other = "1" * 32
    with context(trace_id=other, span_id="0" * 15 + "1"):
        subject.authorize(
            identity(), evaluation_context("018f47a6-7b42-7c00-8000-0000000000a3")
        )
    recorded = [document["trace_id"] for document in repository.adr_documents]
    assert recorded == [CALLER_TRACE, CALLER_TRACE, other]
