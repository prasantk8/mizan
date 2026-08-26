"""Opaque keyset cursors, shared by every list endpoint."""

from __future__ import annotations

import base64
import json
from datetime import datetime

from .problems import Problem


def encode_cursor(created_at: datetime, identifier: str) -> str:
    raw = json.dumps([created_at.isoformat(), identifier], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(value: str) -> tuple[datetime, str]:
    try:
        padded = value + "=" * (-len(value) % 4)
        timestamp, identifier = json.loads(base64.urlsafe_b64decode(padded))
        return datetime.fromisoformat(timestamp), str(identifier)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise Problem(400, "invalid_cursor", "Pagination cursor is malformed") from exc
