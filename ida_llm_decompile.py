"""Optional OpenAI Responses client used by LLM analysis preprocessors."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from openai import OpenAI

from ida_llm_utils import LlmResponseError, extract_json_object, validated_temperature


@dataclass(frozen=True)
class LlmConfig:
    model: str = "gpt-4o"
    api_key: str | None = None
    base_url: str | None = None
    temperature: float | None = None
    effort: str = "medium"
    fake_as: str | None = None
    max_retries: int = 3

    @classmethod
    def from_environment(cls):
        load_dotenv()
        model = os.environ.get("GSVIBE_LLM_MODEL", "gpt-4o").strip()
        if not model:
            raise LlmResponseError("GSVIBE_LLM_MODEL cannot be empty")
        api_key = os.environ.get("GSVIBE_LLM_APIKEY", "").strip() or None
        base_url = os.environ.get("GSVIBE_LLM_BASEURL", "").strip() or None
        fake_as = os.environ.get("GSVIBE_LLM_FAKE_AS", "").strip().lower() or None
        if fake_as not in {None, "codex"}:
            raise LlmResponseError("GSVIBE_LLM_FAKE_AS must be 'codex' when set")
        if fake_as == "codex" and base_url is None:
            raise LlmResponseError("GSVIBE_LLM_BASEURL is required when GSVIBE_LLM_FAKE_AS=codex")
        effort = os.environ.get("GSVIBE_LLM_EFFORT", "medium").strip().lower() or "medium"
        if effort not in {"none", "minimal", "low", "medium", "high", "xhigh"}:
            raise LlmResponseError("GSVIBE_LLM_EFFORT must be one of none, minimal, low, medium, high, xhigh")
        return cls(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=validated_temperature(os.environ.get("GSVIBE_LLM_TEMPERATURE")),
            effort=effort,
            fake_as=fake_as,
        )


def request_json(prompt: str, *, config: LlmConfig | None = None, client=None) -> dict:
    if not isinstance(prompt, str) or not prompt.strip():
        raise LlmResponseError("LLM prompt must be non-empty")
    config = config or LlmConfig.from_environment()
    if client is None and not config.api_key:
        raise LlmResponseError("GSVIBE_LLM_APIKEY is required for LLM analysis")
    client = client or OpenAI(
        api_key=config.api_key,
        base_url=config.base_url,
        max_retries=config.max_retries,
    )
    arguments = {"model": config.model, "input": prompt}
    if config.temperature is not None:
        arguments["temperature"] = config.temperature
    if config.effort != "none":
        arguments["reasoning"] = {"effort": config.effort}
    if config.fake_as is not None:
        arguments["extra_body"] = {"fake_as": config.fake_as}
    response = client.responses.create(**arguments)
    output_text = getattr(response, "output_text", None)
    if not isinstance(output_text, str):
        raise LlmResponseError("OpenAI response did not contain output_text")
    return extract_json_object(output_text)
