"""Optional OpenAI Responses client used by LLM analysis preprocessors."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from openai import OpenAI

from ida_llm_utils import LlmResponseError, extract_json_object, validated_temperature


@dataclass(frozen=True)
class LlmConfig:
    model: str
    api_key: str
    base_url: str | None = None
    temperature: float | None = None
    max_retries: int = 2

    @classmethod
    def from_environment(cls):
        load_dotenv()
        model = os.environ.get("OPENAI_MODEL", "").strip()
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not model or not api_key:
            raise LlmResponseError("OPENAI_MODEL and OPENAI_API_KEY are required for LLM analysis")
        retries = int(os.environ.get("OPENAI_MAX_RETRIES", "2"))
        if not 0 <= retries <= 10:
            raise LlmResponseError("OPENAI_MAX_RETRIES must be between 0 and 10")
        return cls(
            model=model,
            api_key=api_key,
            base_url=os.environ.get("OPENAI_BASE_URL") or None,
            temperature=validated_temperature(os.environ.get("OPENAI_TEMPERATURE")),
            max_retries=retries,
        )


def request_json(prompt: str, *, config: LlmConfig | None = None, client=None) -> dict:
    if not isinstance(prompt, str) or not prompt.strip():
        raise LlmResponseError("LLM prompt must be non-empty")
    config = config or LlmConfig.from_environment()
    client = client or OpenAI(
        api_key=config.api_key,
        base_url=config.base_url,
        max_retries=config.max_retries,
    )
    arguments = {"model": config.model, "input": prompt}
    if config.temperature is not None:
        arguments["temperature"] = config.temperature
    response = client.responses.create(**arguments)
    output_text = getattr(response, "output_text", None)
    if not isinstance(output_text, str):
        raise LlmResponseError("OpenAI response did not contain output_text")
    return extract_json_object(output_text)
