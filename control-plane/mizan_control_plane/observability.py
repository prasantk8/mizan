"""Logs that keep their fields, and counters that leave the process.

Two defects, and the first is the one that costs an incident.

**Structured fields were silently discarded.** `execution.py:514` and `service.py:288` are the two
places this system reports a security-relevant failure, and both pass the identifying context
through `extra=`:

    LOGGER.error("security_event_pool_timeout", extra={"tenant_id": ..., "decision_id": ...})
    LOGGER.critical("system_fail_closed_evidence_write_failed", extra={...})

Under `logging.basicConfig()` the default formatter renders `%(message)s` and nothing else. Both
dictionaries are attached to the record and then never emitted. An operator investigating a
fail-closed evidence write -- the most serious event this control plane can report -- got the
line `system_fail_closed_evidence_write_failed` naming neither the tenant nor the decision. The
call sites were right the whole time; nothing was configured to print what they attached.

**Counters never left the process.** `ExecutionService.security_event_counters` and
`AuthorizationService.failure_counters` accumulate in memory and were read by nothing outside
tests. There was no `/metrics` among the 39 routes.

Both are fixed here without adding a dependency. `JsonLogFormatter` is a `logging.Formatter`
subclass; the Prometheus text exposition format is small, stable and documented, and is rendered
directly. `prometheus_client` was considered and not used: its model wants metrics declared up
front with fixed label sets, while both counters here are keyed by a dynamic event name, and its
global default registry works against a design where the API, the drainer and the attestation
runner are separate processes each holding their own numbers.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

# Attributes `logging` puts on every record. Anything else came from `extra=` and is the whole
# point of this module, so the set is written out rather than guessed at.
_STANDARD_RECORD_FIELDS = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
        "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
        "pathname", "process", "processName", "relativeCreated", "stack_info", "taskName",
        "thread", "threadName",
    }
)

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class JsonLogFormatter(logging.Formatter):
    """One JSON object per record, carrying every field the call site attached.

    A field that cannot be serialised is rendered with `repr` rather than dropped or raising:
    losing the log line is how this class of defect started, and a formatter that can throw
    inside a failure path is worse than one that prints something approximate.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=repr, sort_keys=True)


def configure_logging(level: str = "INFO") -> None:
    """Install JSON logging on the root logger, replacing anything already there.

    `force=True` matters: `basicConfig` is a no-op when the root logger already has a handler, so
    a second caller silently keeps the first caller's plain formatter -- which is one way the
    dropped-fields defect could come back without any call site changing.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    logging.basicConfig(level=level.upper(), handlers=[handler], force=True)


def _escape_label_value(value: str) -> str:
    # Prometheus exposition: backslash, double quote and newline are escaped inside a label
    # value, and nothing else is.
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_help(text: str) -> str:
    # In HELP, backslash and newline are escaped; a double quote is not special.
    return text.replace("\\", "\\\\").replace("\n", "\\n")


class MetricFamily:
    """One metric name, its type, its help text, and its samples.

    Samples carry at most one label because that is all either counter needs: both are keyed by
    a single dynamic event name. A family with no samples still emits its HELP and TYPE lines, so
    a scrape can tell "this counter is zero" from "this build does not have this counter".
    """

    def __init__(self, name: str, kind: str, help_text: str, label: str | None = None) -> None:
        self.name = name
        self.kind = kind
        self.help_text = help_text
        self.label = label
        self.samples: list[tuple[str | None, float]] = []

    def add(self, label_value: str | None, value: float) -> MetricFamily:
        self.samples.append((label_value, value))
        return self

    def extend(self, counts: Mapping[str, int]) -> MetricFamily:
        for label_value, value in sorted(counts.items()):
            self.add(label_value, float(value))
        return self


def render_prometheus(families: Iterable[MetricFamily]) -> str:
    """Render the text exposition format. Deterministic, so a golden test can assert on it."""
    lines: list[str] = []
    for family in families:
        lines.append(f"# HELP {family.name} {_escape_help(family.help_text)}")
        lines.append(f"# TYPE {family.name} {family.kind}")
        for label_value, value in family.samples:
            if family.label is not None and label_value is not None:
                series = f'{family.name}{{{family.label}="{_escape_label_value(label_value)}"}}'
            else:
                series = family.name
            # Integral values render without a trailing `.0`; Prometheus accepts both, and the
            # shorter form is what every other exporter emits.
            rendered = str(int(value)) if float(value).is_integer() else repr(float(value))
            lines.append(f"{series} {rendered}")
    return "\n".join(lines) + "\n"
