"""Deliberate fault switch used only to prove each adversarial category can go red."""

from pathlib import Path

MARKER = Path(__file__).with_name(".regression")


def active(category: str) -> bool:
    return MARKER.exists() and MARKER.read_text(encoding="utf-8").strip() == category
