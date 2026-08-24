from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from .problems import Problem

JSON_FENCE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


class ContractSchemas:
    def __init__(self, spec_path: Path) -> None:
        documents = [json.loads(block) for block in JSON_FENCE.findall(spec_path.read_text())]
        schemas = {item["title"]: item for item in documents if "$id" in item and "title" in item}
        common = schemas["Mizan common definitions"]
        common_id = common["$id"]
        schemas = {
            title: json.loads(json.dumps(schema).replace('"common#', f'"{common_id}#'))
            for title, schema in schemas.items()
        }
        common = schemas["Mizan common definitions"]
        registry = Registry().with_resource(common["$id"], Resource.from_contents(common))
        registry = registry.with_resource("common", Resource.from_contents(common))
        for schema in schemas.values():
            registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
        self.validators = {
            title: Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
            for title, schema in schemas.items()
        }

    def validate(self, title: str, document: dict[str, Any]) -> None:
        try:
            self.validators[title].validate(document)
        except ValidationError as exc:
            pointer = "/" + "/".join(str(part) for part in exc.absolute_path)
            raise Problem(400, "schema_validation_failed", f"{pointer}: {exc.message}") from exc
