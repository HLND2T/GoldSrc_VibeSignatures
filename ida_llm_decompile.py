"""LLM decompile prompt, YAML validation, and Responses transport helpers."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import yaml
from dotenv import load_dotenv
from openai import OpenAI

from ida_llm_utils import LlmResponseError, extract_json_object, validated_temperature


_UNSET = object()
LLM_DECOMPILE_RESULT_SECTIONS = (
    "found_vcall",
    "found_call",
    "found_funcptr",
    "found_gv",
    "found_struct_offset",
)
_LLM_RESULT_SYMBOL_KEYS = {
    "found_vcall": "func_name",
    "found_call": "func_name",
    "found_funcptr": "funcptr_name",
    "found_gv": "gv_name",
}
_LLM_RESULT_REQUIRED_KEYS = {
    "found_vcall": ("insn_va", "insn_disasm", "vfunc_offset", "func_name"),
    "found_call": ("insn_va", "insn_disasm", "func_name"),
    "found_funcptr": ("insn_va", "insn_disasm", "funcptr_name"),
    "found_gv": ("insn_va", "insn_disasm", "gv_name"),
    "found_struct_offset": (
        "insn_va",
        "insn_disasm",
        "offset",
        "size",
        "struct_name",
        "member_name",
    ),
}
_DISASM_ADDRESS_LINE_RE = re.compile(r"^\s*(?:[^:\s]+:)?(?:0x)?([0-9A-Fa-f]{4,16}):?\s+(.+?)\s*$")
_MEMORY_EXPRESSION_RE = re.compile(r"\[([^\]]+)\]")
_MEMORY_DISPLACEMENT_RE = re.compile(r"(?P<sign>[+-])\s*(?P<value>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+[hH]|\d+)")
_MEMORY_BASE_REGISTER_RE = re.compile(r"\b(?:e(?:ax|bx|cx|dx|si|di|bp|sp)|(?:ax|bx|cx|dx|si|di|bp|sp))\b", re.I)


@dataclass(frozen=True)
class LlmConfig:
    model: str = "gpt-4o"
    api_key: str | None = None
    base_url: str | None = None
    temperature: float | None = None
    effort: str = "medium"
    fake_as: str | None = None
    max_retries: int = 3
    retry_initial_delay: float = 1.0
    retry_backoff_factor: float = 2.0
    retry_max_delay: float = 8.0

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


def _normalize_response_messages(messages):
    normalized = []
    for message in messages or ():
        if not isinstance(message, Mapping):
            raise LlmResponseError("LLM messages must be mappings")
        role = str(message.get("role") or "").strip()
        content = str(message.get("content") or "")
        if role not in {"system", "user", "assistant"} or not content.strip():
            raise LlmResponseError("LLM messages must contain a supported role and non-empty content")
        normalized.append({"role": role, "content": content})
    if not normalized:
        raise LlmResponseError("LLM messages must be non-empty")
    return normalized


def request_text(messages, *, config: LlmConfig | None = None, client=None) -> str:
    config = config or LlmConfig.from_environment()
    if client is None and not config.api_key:
        raise LlmResponseError("GSVIBE_LLM_APIKEY is required for LLM analysis")
    client = client or OpenAI(api_key=config.api_key, base_url=config.base_url, max_retries=0)
    arguments = {
        "model": config.model,
        "input": _normalize_response_messages(messages),
    }
    if config.temperature is not None:
        arguments["temperature"] = config.temperature
    if config.effort != "none":
        arguments["reasoning"] = {"effort": config.effort}
    if config.fake_as is not None:
        arguments["extra_body"] = {"fake_as": config.fake_as}
    response = client.responses.create(**arguments)
    output_text = getattr(response, "output_text", None)
    if not isinstance(output_text, str) or not output_text.strip():
        raise LlmResponseError("OpenAI response did not contain output_text")
    return output_text


def request_json(prompt: str, *, config: LlmConfig | None = None, client=None) -> dict:
    if not isinstance(prompt, str) or not prompt.strip():
        raise LlmResponseError("LLM prompt must be non-empty")
    return extract_json_object(request_text([{"role": "user", "content": prompt}], config=config, client=client))


def _empty_llm_decompile_result():
    return {section: [] for section in LLM_DECOMPILE_RESULT_SECTIONS}


def _normalize_retry_attempts(value, default=3):
    try:
        attempts = int(value)
    except (TypeError, ValueError):
        attempts = int(default)
    return max(1, attempts)


def _normalize_retry_delay(value, default, minimum=0.0):
    try:
        delay = float(value)
    except (TypeError, ValueError):
        delay = float(default)
    return max(minimum, delay)


def _extract_error_status_code(exc):
    for source in (exc, getattr(exc, "response", None)):
        status_code = getattr(source, "status_code", None)
        if status_code is None:
            continue
        try:
            return int(status_code)
        except (TypeError, ValueError):
            continue
    return None


def _is_transient_llm_error(exc):
    status_code = _extract_error_status_code(exc)
    if status_code == 429 or (status_code is not None and 500 <= status_code < 600):
        return True
    transient_type_names = {
        "APIConnectionError",
        "APITimeoutError",
        "RateLimitError",
        "InternalServerError",
        "ConnectError",
        "ConnectTimeout",
        "ReadTimeout",
        "WriteTimeout",
        "PoolTimeout",
        "RemoteProtocolError",
        "NetworkError",
        "TimeoutException",
    }
    if any(cls.__name__ in transient_type_names for cls in type(exc).__mro__):
        return True
    message = str(exc or "").lower()
    retryable_fragments = (
        "connection error",
        "connection reset",
        "connection refused",
        "connection aborted",
        "name resolution",
        "dns",
        "transport received error",
        "timeout",
        "timed out",
        "rate limit",
        "rate_limit",
        "too many requests",
        "http 429",
        "status 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "status 500",
        "status 502",
        "status 503",
        "status 504",
        "server error",
        "service unavailable",
        "temporarily unavailable",
    )
    return any(fragment in message for fragment in retryable_fragments)


def _parse_int_value(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if text.lower().endswith("h"):
        text = "0x" + text[:-1]
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def _extract_yaml_candidates(response_text):
    text = str(response_text or "").strip()
    if not text:
        return []
    candidates = [
        match.group(1).strip()
        for match in re.finditer(
            r"```(?:yaml|yml)[ \t]*\n?(.*?)```",
            text,
            re.IGNORECASE | re.DOTALL,
        )
    ]
    if not candidates:
        candidates = [match.group(1).strip() for match in re.finditer(r"```[ \t]*\n(.*?)```", text, re.DOTALL)]
    return candidates or [text]


def _load_yaml_document(response_text):
    candidates = _extract_yaml_candidates(response_text)
    if not candidates:
        return None, [{"issue_type": "yaml_parse_error", "message": "The YAML response was blank."}]
    last_issue = None
    for candidate in candidates:
        try:
            parsed = yaml.load(candidate, Loader=yaml.BaseLoader)
        except yaml.YAMLError as exc:
            last_issue = {
                "issue_type": "yaml_parse_error",
                "message": f"The YAML could not be parsed: {exc}.",
            }
            continue
        if isinstance(parsed, dict):
            return parsed, []
        last_issue = {
            "issue_type": "yaml_root_type_mismatch",
            "message": f"The YAML root must be a mapping, not {type(parsed).__name__}.",
        }
    return None, [last_issue or {"issue_type": "yaml_parse_error", "message": "The YAML response was empty."}]


def _normalize_requested_symbols(symbol_name_list):
    if isinstance(symbol_name_list, (list, tuple, set, frozenset)):
        values = symbol_name_list
    else:
        values = [symbol_name_list]
    return tuple(dict.fromkeys(text for value in values if (text := str(value or "").strip())))


def _entry_is_valid(section_name, entry):
    if not isinstance(entry, dict):
        return False
    return all(
        not isinstance(entry.get(key), (dict, list)) and str(entry.get(key, "") or "").strip()
        for key in _LLM_RESULT_REQUIRED_KEYS[section_name]
    )


def _normalize_entries(section_name, entries):
    if not isinstance(entries, list):
        return []
    return [
        {key: entry[key] for key in _LLM_RESULT_REQUIRED_KEYS[section_name]}
        for entry in entries
        if _entry_is_valid(section_name, entry)
    ]


def _normalize_mapping(mapping):
    return {section: _normalize_entries(section, mapping.get(section, [])) for section in LLM_DECOMPILE_RESULT_SECTIONS}


def _validate_raw_mapping(mapping, *, require_all_sections):
    issues = []
    keys = set(mapping)
    permitted = set(LLM_DECOMPILE_RESULT_SECTIONS)
    if keys - permitted:
        issues.append(
            {
                "issue_type": "yaml_schema_mismatch",
                "message": f"Unknown top-level YAML keys: {', '.join(sorted(keys - permitted))}.",
            }
        )
    if require_all_sections and keys != permitted:
        issues.append(
            {
                "issue_type": "yaml_schema_mismatch",
                "message": "The YAML mapping must contain all five canonical result sections.",
            }
        )
    for section in keys & permitted:
        entries = mapping[section]
        if not isinstance(entries, list):
            issues.append(
                {
                    "issue_type": "yaml_section_type_mismatch",
                    "message": f"{section} must be a list.",
                }
            )
            continue
        for index, entry in enumerate(entries):
            if not _entry_is_valid(section, entry):
                issues.append(
                    {
                        "issue_type": "yaml_entry_shape_mismatch",
                        "message": f"{section}[{index}] is missing required scalar fields.",
                    }
                )
    return issues


def _parse_llm_decompile_response_with_issues(response_text, requested_symbol_names=None):
    parsed, issues = _load_yaml_document(response_text)
    if issues:
        return _empty_llm_decompile_result(), issues
    root_keys = set(parsed)
    permitted = set(LLM_DECOMPILE_RESULT_SECTIONS)
    if root_keys & permitted:
        issues = _validate_raw_mapping(parsed, require_all_sections=True)
        return _normalize_mapping(parsed), issues

    requested = set(_normalize_requested_symbols(requested_symbol_names))
    if not parsed or not root_keys <= requested:
        return _empty_llm_decompile_result(), [
            {
                "issue_type": "yaml_schema_mismatch",
                "message": "Top-level wrapper symbols must all be requested symbols.",
            }
        ]
    flattened = _empty_llm_decompile_result()
    for wrapper_symbol, wrapped in parsed.items():
        if not isinstance(wrapped, dict):
            issues.append(
                {
                    "issue_type": "yaml_schema_mismatch",
                    "message": f"Wrapper {wrapper_symbol!r} must contain a mapping.",
                }
            )
            continue
        issues.extend(_validate_raw_mapping(wrapped, require_all_sections=False))
        for section in set(wrapped) & permitted:
            for entry in wrapped[section] if isinstance(wrapped[section], list) else ():
                symbol_key = _LLM_RESULT_SYMBOL_KEYS.get(section)
                if symbol_key is not None and isinstance(entry, dict) and entry.get(symbol_key) != wrapper_symbol:
                    issues.append(
                        {
                            "issue_type": "wrapped_symbol_mismatch",
                            "message": f"{section} entry does not match wrapper {wrapper_symbol!r}.",
                        }
                    )
                flattened[section].append(entry)
    if not any(flattened.values()):
        issues.append(
            {
                "issue_type": "yaml_schema_mismatch",
                "message": "A wrapped compatibility response must contain at least one result.",
            }
        )
    return _normalize_mapping(flattened), issues


def parse_llm_decompile_response(response_text):
    return _parse_llm_decompile_response_with_issues(response_text)[0]


def _strip_disasm_comments(disasm_code):
    rendered = []
    for line in str(disasm_code or "").splitlines():
        if re.search(r"\s;", line):
            line = re.split(r"\s;", line, maxsplit=1)[0]
        if line.strip():
            rendered.append(line.rstrip())
    return "\n".join(rendered)


def _strip_procedure_comments(procedure):
    text = re.sub(r"/\*.*?\*/", "", str(procedure or ""), flags=re.DOTALL)
    return "\n".join(re.sub(r"//.*$", "", line).rstrip() for line in text.splitlines()).strip()


def render_llm_decompile_blocks(reference_items, target_items):
    def normalize(items):
        if isinstance(items, Mapping):
            return [items]
        return [item for item in items or () if isinstance(item, Mapping)]

    def render(label, item, *, strip_comments):
        disasm = str(item.get("disasm_code") or "")
        procedure = str(item.get("procedure") or "")
        if strip_comments:
            disasm = _strip_disasm_comments(disasm)
            procedure = _strip_procedure_comments(procedure)
        name = str(item.get("func_name") or label)
        return f"{label} function: {name}\n\nDisassembly:\n{disasm}\n\nProcedure:\n{procedure}"

    reference_blocks = "\n\n".join(
        render("Reference", item, strip_comments=False) for item in normalize(reference_items)
    )
    target_blocks = "\n\n".join(render("Target", item, strip_comments=True) for item in normalize(target_items))
    return reference_blocks, target_blocks


def _normalize_disasm_whitespace(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _build_target_disasm_index(target_disasm_codes, disasm_code=""):
    if target_disasm_codes is None:
        codes = [disasm_code]
    elif isinstance(target_disasm_codes, str):
        codes = [target_disasm_codes]
    else:
        codes = list(target_disasm_codes or ())
    instructions_by_va = {}
    addresses_by_instruction = {}
    for code in codes:
        for line in _strip_disasm_comments(code).splitlines():
            match = _DISASM_ADDRESS_LINE_RE.match(line)
            if match is None:
                continue
            instruction = _normalize_disasm_whitespace(match.group(2))
            if not instruction or instruction.startswith(";"):
                continue
            insn_va = int(match.group(1), 16)
            instructions_by_va.setdefault(insn_va, set()).add(instruction)
            addresses_by_instruction.setdefault(instruction, set()).add(insn_va)
    return instructions_by_va, addresses_by_instruction


def _normalize_expected_result_sections(expected_result_sections):
    if not isinstance(expected_result_sections, Mapping):
        return {}
    normalized = {}
    for symbol_name, sections in expected_result_sections.items():
        name = str(symbol_name or "").strip()
        if isinstance(sections, str):
            sections = [sections]
        if not name or not isinstance(sections, (tuple, list, set)):
            continue
        values = tuple(dict.fromkeys(section for section in sections if section in LLM_DECOMPILE_RESULT_SECTIONS))
        if values:
            normalized[name] = values
    return normalized


def _normalize_instruction_validations(instruction_validations):
    if instruction_validations is None:
        return {}
    if not isinstance(instruction_validations, Mapping):
        return None
    normalized = {}
    for symbol_name, raw in instruction_validations.items():
        if not isinstance(raw, Mapping):
            return None
        rules = raw.get("instruction_rules") or ()
        if not isinstance(rules, (tuple, list)):
            return None
        normalized_rules = []
        for rule in rules:
            if not isinstance(rule, Mapping) or set(rule) != {"regex", "text"}:
                return None
            try:
                compiled = re.compile(str(rule["regex"]))
            except re.error:
                return None
            normalized_rules.append((compiled, str(rule["text"])))
        normalized[str(symbol_name)] = {
            "instruction_rules": normalized_rules,
            "expected_size": raw.get("expected_size"),
        }
    return normalized


def _entry_symbol(section, entry):
    if section == "found_struct_offset":
        struct_name = str(entry.get("struct_name") or "").strip()
        member_name = str(entry.get("member_name") or "").strip()
        return f"{struct_name}_{member_name}".replace(".", "_")
    return str(entry.get(_LLM_RESULT_SYMBOL_KEYS[section]) or "").strip()


def _memory_displacements(instruction):
    values = set()
    for expression in _MEMORY_EXPRESSION_RE.findall(str(instruction or "")):
        found_explicit_displacement = False
        for match in _MEMORY_DISPLACEMENT_RE.finditer(expression):
            value = _parse_int_value(match.group("value"))
            if value is not None:
                found_explicit_displacement = True
                values.add(-value if match.group("sign") == "-" else value)
        if not found_explicit_displacement and _MEMORY_BASE_REGISTER_RE.search(expression):
            values.add(0)
    return values


def _validate_llm_result(
    result,
    *,
    requested_symbols,
    expected_sections,
    instruction_validations,
    disasm_index,
):
    issues = []
    requested = set(requested_symbols)
    instructions_by_va, addresses_by_instruction = disasm_index
    for section in LLM_DECOMPILE_RESULT_SECTIONS:
        for index, entry in enumerate(result[section]):
            symbol_name = _entry_symbol(section, entry)
            if symbol_name not in requested:
                issues.append(
                    {
                        "issue_type": "unexpected_result_symbol",
                        "message": f"{section}[{index}] identifies unrequested symbol {symbol_name!r}.",
                    }
                )
                continue
            if section not in expected_sections.get(symbol_name, ()):
                issues.append(
                    {
                        "issue_type": "unexpected_result_section",
                        "message": f"{symbol_name!r} is not allowed in {section}.",
                    }
                )
            insn_va = _parse_int_value(entry.get("insn_va"))
            reported_disasm = _normalize_disasm_whitespace(entry.get("insn_disasm"))
            actual_disasms = instructions_by_va.get(insn_va, set()) if insn_va is not None else set()
            if reported_disasm not in actual_disasms:
                issues.append(
                    {
                        "issue_type": "instruction_mismatch",
                        "message": (
                            f"{section}[{index}] instruction {entry.get('insn_va')!r} / {reported_disasm!r} "
                            "does not match target disassembly."
                        ),
                        "candidate_vas": sorted(addresses_by_instruction.get(reported_disasm, set())),
                    }
                )
            validation = instruction_validations.get(symbol_name, {})
            instruction_rules = validation.get("instruction_rules", ())
            if instruction_rules and not any(regex.fullmatch(reported_disasm) for regex, _text in instruction_rules):
                issues.append(
                    {
                        "issue_type": "instruction_rule_mismatch",
                        "message": (
                            f"{section}[{index}] must match one of: "
                            + ", ".join(repr(text) for _regex, text in instruction_rules)
                            + "."
                        ),
                    }
                )
            if section == "found_vcall":
                offset = _parse_int_value(entry.get("vfunc_offset"))
                if offset is None or offset not in _memory_displacements(reported_disasm):
                    issues.append(
                        {
                            "issue_type": "vcall_offset_mismatch",
                            "message": f"{section}[{index}] does not contain its vfunc_offset displacement.",
                        }
                    )
            if section == "found_struct_offset":
                offset = _parse_int_value(entry.get("offset"))
                if offset is None or offset not in _memory_displacements(reported_disasm):
                    issues.append(
                        {
                            "issue_type": "struct_offset_mismatch",
                            "message": f"{section}[{index}] does not contain its offset displacement.",
                        }
                    )
                expected_size = _parse_int_value(validation.get("expected_size"))
                actual_size = _parse_int_value(entry.get("size"))
                if expected_size is not None and actual_size != expected_size:
                    issues.append(
                        {
                            "issue_type": "struct_size_mismatch",
                            "message": f"{section}[{index}] size does not match expected_size.",
                        }
                    )
    return issues


def _build_section_requirements(expected_sections):
    if not expected_sections:
        return ""
    lines = ["Required result sections:"]
    for symbol_name, sections in expected_sections.items():
        lines.append(f"- {symbol_name}: {' or '.join(sorted(sections))}")
    return "\n".join(lines)


def _build_correction_prompt(issues):
    issue_text = "\n".join(f"- {issue['message']}" for issue in issues)
    return (
        "Your previous YAML output is invalid.\n"
        f"Problems:\n{issue_text}\n\n"
        "Return the complete YAML mapping, not a patch or partial document. It must contain exactly "
        "found_vcall, found_call, found_funcptr, found_gv, and found_struct_offset. Every entry must "
        "contain the required scalar fields, and each insn_va / insn_disasm pair must exactly match the "
        "target disassembly except for whitespace. Return no explanation or text outside the complete YAML."
    )


def _resolve_template(value, platform, module_name):
    return (
        str(value or "")
        .replace("{platform}", str(platform or "").strip())
        .replace("{module_name}", module_name)
        .replace("{module}", module_name)
    )


def _build_llm_decompile_request_cache_key(llm_request):
    if not isinstance(llm_request, Mapping):
        return None
    model = str(llm_request.get("model") or "").strip()
    prompt_path = str(llm_request.get("prompt_path") or "").strip()
    reference_paths = llm_request.get("reference_yaml_paths")
    if isinstance(reference_paths, str):
        reference_paths = [reference_paths]
    if not isinstance(reference_paths, (tuple, list)):
        return None
    reference_paths = tuple(str(path).strip() for path in reference_paths if str(path).strip())
    if not model or not prompt_path or not reference_paths:
        return None
    return model, prompt_path, reference_paths, llm_request.get("temperature")


def _default_transport(**kwargs):
    config = LlmConfig(
        model=str(kwargs.get("model") or "gpt-4o"),
        api_key=kwargs.get("api_key"),
        base_url=kwargs.get("base_url"),
        temperature=kwargs.get("temperature"),
        effort=str(kwargs.get("effort") or "medium"),
        fake_as=kwargs.get("fake_as"),
        max_retries=1,
    )
    return request_text(kwargs["messages"], config=config, client=kwargs.get("client"))


async def _invoke_transport(transport, request_kwargs):
    value = await asyncio.to_thread(transport, **request_kwargs)
    if inspect.isawaitable(value):
        value = await value
    if not isinstance(value, str):
        raise LlmResponseError("LLM transport did not return text")
    return value


async def call_llm_decompile(
    *,
    client=None,
    model=None,
    symbol_name_list=None,
    expected_result_sections=None,
    disasm_code="",
    target_disasm_codes=None,
    procedure="",
    disasm_for_reference="",
    procedure_for_reference="",
    reference_blocks=None,
    target_blocks=None,
    prompt_template=None,
    platform=None,
    new_binary_dir=None,
    temperature=None,
    effort=None,
    api_key=None,
    base_url=None,
    fake_as=None,
    max_retries=None,
    retry_initial_delay=None,
    retry_backoff_factor=None,
    retry_max_delay=None,
    debug=False,
    instruction_validations=None,
    call_llm_text_func=_UNSET,
):
    del debug
    transport = _default_transport if call_llm_text_func is _UNSET else call_llm_text_func
    if not callable(transport):
        return _empty_llm_decompile_result()
    requested_symbols = _normalize_requested_symbols(symbol_name_list)
    expected_sections = _normalize_expected_result_sections(expected_result_sections)
    validations = _normalize_instruction_validations(instruction_validations)
    if not requested_symbols or not expected_sections or validations is None:
        return _empty_llm_decompile_result()
    module_name = Path(new_binary_dir).resolve().name if new_binary_dir else ""
    if reference_blocks is None or target_blocks is None:
        fallback_reference, fallback_target = render_llm_decompile_blocks(
            [
                {
                    "func_name": "Reference",
                    "disasm_code": disasm_for_reference,
                    "procedure": procedure_for_reference,
                }
            ],
            [
                {
                    "func_name": "Target",
                    "disasm_code": disasm_code,
                    "procedure": procedure,
                }
            ],
        )
        reference_blocks = reference_blocks if reference_blocks is not None else fallback_reference
        target_blocks = target_blocks if target_blocks is not None else fallback_target
    try:
        template = _resolve_template(prompt_template or "", platform, module_name)
        prompt = template.format(
            symbol_name_list=", ".join(requested_symbols),
            disasm_for_reference=str(disasm_for_reference or ""),
            procedure_for_reference=str(procedure_for_reference or ""),
            disasm_code=str(disasm_code or ""),
            procedure=str(procedure or ""),
            reference_blocks=str(reference_blocks or ""),
            target_blocks=str(target_blocks or ""),
            platform=str(platform or "").strip(),
            module_name=module_name,
            module=module_name,
        )
    except Exception:
        return _empty_llm_decompile_result()
    requirements = _build_section_requirements(expected_sections)
    if requirements:
        prompt = f"{prompt}\n\n{requirements}"
    messages = [
        {"role": "system", "content": "You are a reverse engineering expert."},
        {"role": "user", "content": prompt},
    ]
    request_kwargs = {
        "model": str(model or "").strip(),
        "messages": list(messages),
        "temperature": temperature,
        "effort": effort,
        "api_key": api_key,
        "base_url": base_url,
        "fake_as": fake_as,
    }
    if client is not None:
        request_kwargs["client"] = client
    attempts = _normalize_retry_attempts(max_retries, default=3)
    delay = _normalize_retry_delay(retry_initial_delay, default=1.0)
    backoff = _normalize_retry_delay(retry_backoff_factor, default=2.0, minimum=1.0)
    max_delay = _normalize_retry_delay(retry_max_delay, default=8.0)
    disasm_index = _build_target_disasm_index(target_disasm_codes, disasm_code)
    for attempt_index in range(attempts):
        request_kwargs["messages"] = list(messages)
        try:
            content = await _invoke_transport(transport, request_kwargs)
        except Exception as exc:
            if not _is_transient_llm_error(exc) or attempt_index >= attempts - 1:
                return _empty_llm_decompile_result()
            if delay > 0:
                await asyncio.sleep(delay)
            delay = min(delay * backoff, max_delay)
            continue
        result, schema_issues = _parse_llm_decompile_response_with_issues(content, requested_symbols)
        semantic_issues = _validate_llm_result(
            result,
            requested_symbols=requested_symbols,
            expected_sections=expected_sections,
            instruction_validations=validations,
            disasm_index=disasm_index,
        )
        issues = schema_issues + semantic_issues
        if not issues:
            return result
        if attempt_index >= attempts - 1:
            return _empty_llm_decompile_result()
        messages.extend(
            [
                {"role": "assistant", "content": content},
                {"role": "user", "content": _build_correction_prompt(issues)},
            ]
        )
    return _empty_llm_decompile_result()
