"""Dispatch one skill-specific preprocessor through a bound IDA MCP session."""

from __future__ import annotations

import importlib.util
import inspect
import json
import re
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

from ida_mcp_session import open_ida_mcp_session

SAFE_SKILL_RE = re.compile(r"^[A-Za-z0-9_.-]+$", re.ASCII)
IMAGE_BASE_RE = re.compile(r"^0x[0-9A-Fa-f]+$", re.ASCII)
_SCRIPT_DIR = Path(__file__).resolve().parent / "ida_preprocessor_scripts"
_PREPROCESS_EXPORT_NAME = "preprocess_skill"
_SCRIPT_ENTRY_CACHE: dict[str, Callable | None] = {}


class PreprocessStatus(str):
    def __new__(cls, value: str, truthy: bool):
        instance = super().__new__(cls, value)
        instance._truthy = bool(truthy)
        return instance

    def __bool__(self) -> bool:
        return self._truthy


PREPROCESS_STATUS_SUCCESS = PreprocessStatus("success", True)
PREPROCESS_STATUS_FAILED = PreprocessStatus("failed", False)
PREPROCESS_STATUS_ABSENT_OK = PreprocessStatus("absent_ok", True)
PREPROCESS_STATUS_NO_SCRIPT = PreprocessStatus("no_script", False)


def _redact_message(message: object, secrets=()) -> str:
    result = str(message)
    for secret in secrets:
        if isinstance(secret, str) and secret:
            result = result.replace(secret, "<redacted>")
    return result


def _emit_diagnostic(
    reason: str,
    skill_name: str,
    message: object,
    *,
    diagnostic_callback=None,
    debug: bool = False,
    exception: BaseException | None = None,
    secrets=(),
) -> None:
    redacted = _redact_message(message, secrets)
    payload = {
        "reason": reason,
        "skill": skill_name,
        "exception_type": type(exception).__name__ if exception is not None else None,
        "message": redacted,
    }
    if diagnostic_callback is not None:
        diagnostic_callback(dict(payload))
    print(f"Preprocess {reason} for {skill_name}: {redacted}", file=sys.stderr)
    if debug and exception is not None:
        formatted = "".join(traceback.format_exception(type(exception), exception, exception.__traceback__))
        print(_redact_message(formatted, secrets), file=sys.stderr, end="")


def _script_path(skill_name: str) -> Path:
    if not SAFE_SKILL_RE.fullmatch(str(skill_name)):
        raise ValueError(f"Unsafe skill name: {skill_name!r}")
    root = Path(_SCRIPT_DIR).resolve()
    path = (root / f"{skill_name}.py").resolve()
    if path.parent != root:
        raise ValueError(f"Preprocessor path escapes script directory: {path}")
    return path


def _validate_preprocess_signature(function: Callable) -> None:
    signature = inspect.signature(function)
    arguments = {
        "session": object(),
        "skill_name": "skill",
        "expected_outputs": [],
        "old_yaml_map": None,
        "new_binary_dir": "directory",
        "platform": "windows",
        "image_base": 0,
        "debug": False,
    }
    if "llm_config" in signature.parameters:
        arguments["llm_config"] = {}
    signature.bind(**arguments)


def _get_preprocess_entry(skill_name: str, *, diagnostic_callback=None, debug: bool = False):
    if skill_name in _SCRIPT_ENTRY_CACHE:
        return _SCRIPT_ENTRY_CACHE[skill_name]
    try:
        path = _script_path(skill_name)
    except ValueError as exc:
        _emit_diagnostic(
            "load_failed",
            skill_name,
            exc,
            diagnostic_callback=diagnostic_callback,
            debug=debug,
            exception=exc,
        )
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None
    if not path.is_file():
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None
    module_name = "ida_preprocessor_script_" + re.sub(r"[^0-9A-Za-z_]", "_", skill_name)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        _emit_diagnostic(
            "load_failed",
            skill_name,
            f"Unable to load module spec for {path}",
            diagnostic_callback=diagnostic_callback,
            debug=debug,
        )
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - import failures become a stable failed status.
        _emit_diagnostic(
            "import_failed",
            skill_name,
            exc,
            diagnostic_callback=diagnostic_callback,
            debug=debug,
            exception=exc,
        )
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None
    function = getattr(module, _PREPROCESS_EXPORT_NAME, None)
    if not callable(function):
        _emit_diagnostic(
            "missing_export",
            skill_name,
            f"Script {path} does not export callable {_PREPROCESS_EXPORT_NAME}",
            diagnostic_callback=diagnostic_callback,
            debug=debug,
        )
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None
    try:
        _validate_preprocess_signature(function)
    except (TypeError, ValueError) as exc:
        _emit_diagnostic(
            "load_failed",
            skill_name,
            f"Invalid preprocess_skill signature: {exc}",
            diagnostic_callback=diagnostic_callback,
            debug=debug,
            exception=exc,
        )
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        return None
    _SCRIPT_ENTRY_CACHE[skill_name] = function
    return function


def _parse_tool_payload(result) -> dict | None:
    if isinstance(result, dict):
        return result
    structured = getattr(result, "structuredContent", None)
    if not isinstance(structured, dict):
        structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content", None) or []
    text = getattr(content[0], "text", None) if content else None
    if not isinstance(text, str):
        return None
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _parse_image_base(result) -> int:
    payload = _parse_tool_payload(result)
    value = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(value, str) or IMAGE_BASE_RE.fullmatch(value) is None:
        raise ValueError("py_eval returned an invalid image base")
    return int(value, 16)


def _normalize_preprocess_status(result):
    if result is True or result == PREPROCESS_STATUS_SUCCESS:
        return PREPROCESS_STATUS_SUCCESS
    if result == PREPROCESS_STATUS_ABSENT_OK:
        return PREPROCESS_STATUS_ABSENT_OK
    if result == PREPROCESS_STATUS_NO_SCRIPT:
        return PREPROCESS_STATUS_NO_SCRIPT
    return PREPROCESS_STATUS_FAILED


async def preprocess_single_skill_via_mcp(
    host,
    port,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    expected_inputs=None,
    optional_inputs=None,
    expected_binary=None,
    explicit_database=None,
    llm_model=None,
    llm_apikey=None,
    llm_baseurl=None,
    llm_temperature=None,
    llm_effort=None,
    llm_fake_as=None,
    llm_max_retries=None,
    symbol_aliases=None,
    debug=False,
    diagnostic_callback=None,
):
    """Run one cached skill preprocessor and return a stable four-value status."""

    try:
        path = _script_path(skill_name)
    except ValueError as exc:
        _emit_diagnostic(
            "load_failed",
            skill_name,
            exc,
            diagnostic_callback=diagnostic_callback,
            debug=debug,
            exception=exc,
        )
        return PREPROCESS_STATUS_FAILED
    if not path.is_file():
        _SCRIPT_ENTRY_CACHE[skill_name] = None
        _emit_diagnostic(
            "no_script",
            skill_name,
            f"No preprocessor script at {path}",
            diagnostic_callback=diagnostic_callback,
            debug=debug,
        )
        return PREPROCESS_STATUS_NO_SCRIPT
    function = _get_preprocess_entry(
        skill_name,
        diagnostic_callback=diagnostic_callback,
        debug=debug,
    )
    if function is None:
        return PREPROCESS_STATUS_FAILED

    secrets = (llm_apikey,)
    try:
        async with open_ida_mcp_session(
            host,
            port,
            expected_binary=expected_binary,
            explicit_database=explicit_database,
        ) as session:
            try:
                image_base_result = await session.call_tool(
                    name="py_eval",
                    arguments={"code": "hex(idaapi.get_imagebase())"},
                )
                image_base = _parse_image_base(image_base_result)
            except Exception as exc:  # noqa: BLE001 - MCP/image-base failures use the failed status contract.
                _emit_diagnostic(
                    "mcp_failed",
                    skill_name,
                    exc,
                    diagnostic_callback=diagnostic_callback,
                    debug=debug,
                    exception=exc,
                    secrets=secrets,
                )
                return PREPROCESS_STATUS_FAILED

            llm_config = {
                "model": llm_model,
                "api_key": llm_apikey,
                "base_url": llm_baseurl,
                "temperature": llm_temperature,
                "effort": llm_effort,
                "fake_as": llm_fake_as,
            }
            if symbol_aliases:
                llm_config["symbol_aliases"] = symbol_aliases
            if llm_max_retries is not None:
                llm_config["max_retries"] = llm_max_retries
            llm_config["_expected_inputs"] = list(expected_inputs or [])
            llm_config["_optional_inputs"] = list(optional_inputs or [])
            arguments = {
                "session": session,
                "skill_name": skill_name,
                "expected_outputs": expected_outputs,
                "old_yaml_map": old_yaml_map,
                "new_binary_dir": new_binary_dir,
                "platform": platform,
                "image_base": image_base,
                "debug": debug,
            }
            if "llm_config" in inspect.signature(function).parameters:
                arguments["llm_config"] = llm_config
            try:
                raw_status = function(**arguments)
                if inspect.isawaitable(raw_status):
                    raw_status = await raw_status
            except Exception as exc:  # noqa: BLE001 - script failures fall back through a stable failed status.
                _emit_diagnostic(
                    "script_failed",
                    skill_name,
                    exc,
                    diagnostic_callback=diagnostic_callback,
                    debug=debug,
                    exception=exc,
                    secrets=secrets,
                )
                return PREPROCESS_STATUS_FAILED
            status = _normalize_preprocess_status(raw_status)
            known_failure = raw_status is False or raw_status is None or raw_status == PREPROCESS_STATUS_FAILED
            if status is PREPROCESS_STATUS_FAILED and not known_failure:
                _emit_diagnostic(
                    "invalid_status",
                    skill_name,
                    f"Unsupported preprocessor status: {raw_status!r}",
                    diagnostic_callback=diagnostic_callback,
                    debug=debug,
                    secrets=secrets,
                )
            return status
    except Exception as exc:  # noqa: BLE001 - connection/setup failures use the same stable failed status.
        _emit_diagnostic(
            "mcp_failed",
            skill_name,
            exc,
            diagnostic_callback=diagnostic_callback,
            debug=debug,
            exception=exc,
            secrets=secrets,
        )
        return PREPROCESS_STATUS_FAILED
