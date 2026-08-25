from __future__ import annotations

from .models import EvaluationContext


class RegistryFloorRiskProvider:
    """Safe walking-skeleton provider until the external risk engine is integrated."""

    def evaluate(self, context: EvaluationContext, floor: str) -> dict:
        return {"level": floor, "floor_source": "tool_registry_floor", "factors": []}
