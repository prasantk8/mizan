"""Logs that keep their fields, and counters that leave the process.

The first test is the important one, and it is written as a comparison rather than an assertion
about the new formatter alone: it shows the *old* configuration dropping the fields and the new
one keeping them, against the real call-site shape. A test that only asserted the new behaviour
would not have told anyone that the old behaviour was broken.
"""

from __future__ import annotations

import json
import logging

import pytest
from mizan_control_plane.observability import (
    JsonLogFormatter,
    MetricFamily,
    configure_logging,
    render_prometheus,
)


def _emit(formatter: logging.Formatter, **extra: object) -> str:
    logger = logging.getLogger("mizan.test.emit")
    record = logger.makeRecord(
        "mizan.test.emit", logging.ERROR, __file__, 1, "security_event_pool_timeout", (), None
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return formatter.format(record)


def test_the_default_formatter_drops_what_the_call_sites_attach() -> None:
    """`execution.py:514` and `service.py:288` both report through `extra=`.

    Under the `logging.basicConfig()` this system used, the default format is `%(message)s`, so
    both dictionaries were attached to the record and never printed. The operator investigating
    a fail-closed evidence write got a line naming neither the tenant nor the decision. This
    asserts the defect rather than describing it, so the fix below has something to be measured
    against.
    """
    old = logging.Formatter()  # exactly what basicConfig() installs by default
    rendered = _emit(old, tenant_id="tnt_bank-a", decision_id="dec-1")

    assert rendered == "security_event_pool_timeout"
    assert "tnt_bank-a" not in rendered
    assert "dec-1" not in rendered


def test_the_json_formatter_keeps_every_field_the_call_site_attached() -> None:
    rendered = _emit(JsonLogFormatter(), tenant_id="tnt_bank-a", decision_id="dec-1")
    payload = json.loads(rendered)

    assert payload["event"] == "security_event_pool_timeout"
    assert payload["tenant_id"] == "tnt_bank-a"
    assert payload["decision_id"] == "dec-1"
    assert payload["level"] == "ERROR"
    assert payload["logger"] == "mizan.test.emit"
    assert payload["timestamp"].endswith("+00:00")


def test_an_unserialisable_field_is_rendered_rather_than_losing_the_line() -> None:
    """A formatter that raises inside a failure path is worse than one that approximates.

    This matters because the two call sites that use `extra=` are both on error paths, and one
    of them is the fail-closed evidence write -- the last line anyone gets before the request
    is refused.
    """

    class Opaque:
        def __repr__(self) -> str:
            return "<opaque>"

    payload = json.loads(_emit(JsonLogFormatter(), thing=Opaque()))
    assert payload["thing"] == "<opaque>"


def test_an_exception_is_carried_as_a_field_not_appended_to_the_message() -> None:
    logger = logging.getLogger("mizan.test.exc")
    try:
        raise ValueError("evidence write failed")
    except ValueError:
        import sys

        record = logger.makeRecord(
            "mizan.test.exc", logging.CRITICAL, __file__, 1, "system_fail_closed", (), sys.exc_info()
        )
    payload = json.loads(JsonLogFormatter().format(record))

    assert payload["event"] == "system_fail_closed"
    assert "ValueError: evidence write failed" in payload["exception"]


def test_configure_logging_replaces_a_handler_that_is_already_installed() -> None:
    """`basicConfig` is a no-op once the root logger has a handler.

    Without `force=True` a process that logged anything before configuration would silently keep
    the plain formatter, and the dropped-fields defect would return with no call site changing.
    """
    root = logging.getLogger()
    original = list(root.handlers)
    try:
        logging.basicConfig(level=logging.INFO, force=True)  # a plain handler, installed first
        configure_logging("INFO")
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonLogFormatter)
    finally:
        root.handlers = original


def test_the_exposition_format_is_rendered_exactly() -> None:
    """A golden assertion, because a scrape that misparses fails silently.

    Prometheus rejects a malformed family by dropping it, so a subtly wrong exposition looks
    identical to a metric that is simply absent -- which is the shape of every other defect in
    this stage.
    """
    families = [
        MetricFamily(
            "mizan_security_events_total", "counter", "Security events, by name.", label="event"
        ).extend({"security_event_pool_timeout": 3, "execution_token_consumed": 1}),
        MetricFamily("mizan_up", "gauge", "Always 1.").add(None, 1),
    ]

    assert render_prometheus(families) == (
        "# HELP mizan_security_events_total Security events, by name.\n"
        "# TYPE mizan_security_events_total counter\n"
        'mizan_security_events_total{event="execution_token_consumed"} 1\n'
        'mizan_security_events_total{event="security_event_pool_timeout"} 3\n'
        "# HELP mizan_up Always 1.\n"
        "# TYPE mizan_up gauge\n"
        "mizan_up 1\n"
    )


def test_a_family_with_no_samples_still_declares_itself() -> None:
    """"No such events" and "this build cannot report them" are different facts."""
    rendered = render_prometheus(
        [MetricFamily("mizan_security_events_total", "counter", "Security events.", label="event")]
    )
    assert rendered == (
        "# HELP mizan_security_events_total Security events.\n"
        "# TYPE mizan_security_events_total counter\n"
    )


@pytest.mark.parametrize(
    ("label_value", "expected"),
    [
        ('quote"inside', 'quote\\"inside'),
        ("back\\slash", "back\\\\slash"),
        ("new\nline", "new\\nline"),
    ],
)
def test_label_values_are_escaped_per_the_exposition_format(
    label_value: str, expected: str
) -> None:
    """Counter keys are dynamic event names, so a hostile or merely odd one must not be able to
    break out of the label and corrupt every following series in the scrape."""
    rendered = render_prometheus(
        [MetricFamily("mizan_events_total", "counter", "Events.", label="event").add(label_value, 1)]
    )
    assert f'mizan_events_total{{event="{expected}"}} 1' in rendered


def test_help_text_escapes_backslash_and_newline_but_not_quotes() -> None:
    rendered = render_prometheus([MetricFamily("m", "gauge", 'a "quoted" \\ thing\nhere')])
    assert '# HELP m a "quoted" \\\\ thing\\nhere' in rendered
