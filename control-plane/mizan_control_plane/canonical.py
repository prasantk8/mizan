from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

from .problems import Problem


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def pointer_get(document: Any, pointer: str) -> Any:
    current = document
    if pointer == "":
        return current
    for encoded in pointer.removeprefix("/").split("/"):
        part = encoded.replace("~1", "/").replace("~0", "~")
        try:
            current = current[int(part)] if isinstance(current, list) else current[part]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise Problem(400, "unclassified_argument", f"Binding pointer not found: {pointer}") from exc
    return current


def binding_hash(parameters: dict[str, Any], pointers: list[str]) -> str:
    if not pointers:
        raise Problem(422, "invalid_binding_profile", "Binding profile has no bound pointers")
    return canonical_hash({pointer: pointer_get(parameters, pointer) for pointer in sorted(pointers)})

