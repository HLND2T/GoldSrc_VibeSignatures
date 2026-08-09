"""Small, testable helpers shared by optional LLM preprocessors."""

from __future__ import annotations

import json
import re


class LlmResponseError(ValueError):
    pass


def extract_json_object(text: str) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise LlmResponseError("LLM response is empty")
    stripped = text.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, re.DOTALL | re.IGNORECASE)
    if fenced:
        stripped = fenced.group(1)
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise LlmResponseError(f"LLM response is not a JSON object: {exc}") from exc
    if not isinstance(value, dict):
        raise LlmResponseError("LLM response top level must be an object")
    return value


def validated_temperature(value: float | str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        temperature = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("LLM temperature must be numeric") from exc
    if not 0 <= temperature <= 2:
        raise ValueError("LLM temperature must be between 0 and 2")
    return temperature
