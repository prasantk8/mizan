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
            raise Problem(
                400, "unclassified_argument", f"Binding pointer not found: {pointer}"
            ) from exc
    return current


def binding_hash(parameters: dict[str, Any], pointers: list[str]) -> str:
    if not pointers:
        raise Problem(422, "invalid_binding_profile", "Binding profile has no bound pointers")
    return canonical_hash(
        {pointer: pointer_get(parameters, pointer) for pointer in sorted(pointers)}
    )


def validate_binding_arguments(
    parameters: dict[str, Any], bound_pointers: list[str], volatile_pointers: list[str]
) -> None:
    classified = [*bound_pointers, *volatile_pointers]
    if not bound_pointers or set(bound_pointers) & set(volatile_pointers):
        raise Problem(422, "invalid_binding_profile", "Binding pointer classes are invalid")

    def visit(value: Any, pointer: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                visit(child, f"{pointer}/{escaped}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{pointer}/{index}")
        elif not any(pointer == known or pointer.startswith(known + "/") for known in classified):
            raise Problem(400, "unclassified_argument", f"Argument has no binding class: {pointer}")

    visit(parameters, "")
