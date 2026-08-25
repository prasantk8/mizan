from __future__ import annotations

import hashlib
import math
from typing import Any

import rfc8785

from .problems import Problem


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def validate_argument_budget(arguments: dict[str, Any]) -> None:
    total_keys = 0
    stack: list[tuple[Any, int]] = [(arguments, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > 16:
            raise Problem(400, "arguments_too_deep", "Tool arguments exceed depth 16")
        if isinstance(value, dict):
            total_keys += len(value)
            if total_keys > 256:
                raise Problem(400, "arguments_too_many_keys", "Tool arguments exceed 256 keys")
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise Problem(400, "arguments_non_finite", "Tool arguments require finite numbers")
    try:
        size = len(rfc8785.dumps(arguments))
    except (ValueError, TypeError) as exc:
        raise Problem(
            400, "arguments_not_canonical", "Tool arguments are not canonical JSON"
        ) from exc
    if size > 65_536:
        raise Problem(413, "arguments_too_large", "Tool arguments exceed 65536 canonical bytes")


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
    validate_argument_budget(parameters)
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
