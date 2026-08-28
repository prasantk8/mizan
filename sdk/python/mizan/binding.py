"""Client-side parameter binding.

This is a second, independent implementation of the binding hash the control plane computes. That
is deliberate: the server recomputes it from the pointers *its own registry* declares and answers
400 `parameters_hash_mismatch` on disagreement, so the two computations check each other. A client
that imported the server's function would prove nothing.

The rule (SPEC §2.6, ADR-008): take each bound JSON Pointer in sorted order, read its value out of
the arguments, and hash the resulting `{pointer: value}` map under RFC 8785 with SHA-256.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


class UnclassifiedArgument(ValueError):
    """A bound pointer names something the arguments do not contain."""


def read_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    current = document
    for encoded in pointer.removeprefix("/").split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        try:
            current = current[int(part)] if isinstance(current, list) else current[part]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise UnclassifiedArgument(f"binding pointer not found: {pointer}") from exc
    return current


def parameters_hash(arguments: dict[str, Any], bound_pointers: list[str]) -> str:
    if not bound_pointers:
        raise UnclassifiedArgument("binding profile declares no bound pointers")
    bound = {pointer: read_pointer(arguments, pointer) for pointer in sorted(bound_pointers)}
    return hashlib.sha256(rfc8785.dumps(bound)).hexdigest()
