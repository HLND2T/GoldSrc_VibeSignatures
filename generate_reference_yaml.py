#!/usr/bin/env python3
"""Generate one annotated LLM decompile reference YAML from a GoldSrc IDB."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import os
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from binary_format import BinaryFormatError, inspect_binary, validate_binary
from ida_analyze_util import (
    build_function_detail_export_py_eval,
    build_remote_text_export_py_eval,
    parse_mcp_result,
)
from ida_mcp_session import (
    McpConnectionError,
    McpDatabaseSelectionError,
    McpToolCallError,
    normalize_binary_identity_path,
    open_ida_mcp_session,
)

MAX_X86_ADDRESS = 0xFFFFFFFF
REFERENCE_YAML_FIELDS = frozenset({"func_name", "func_va", "disasm_code", "procedure"})


class ReferenceGenerationError(RuntimeError):
    pass


class LiteralDumper(yaml.SafeDumper):
    pass


def _literal_str_representer(dumper: yaml.Dumper, value: str) -> yaml.Node:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


LiteralDumper.add_representer(str, _literal_str_representer)


def _normalize_non_empty_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _normalize_address_text(value: Any, *, require_string: bool = False) -> str | None:
    if require_string and not isinstance(value, str):
        return None

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            address = int(text, 0)
        except (TypeError, ValueError):
            return None
        return text if 0 <= address <= MAX_X86_ADDRESS else None

    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_X86_ADDRESS:
        return hex(value)

    return None


def _validate_reference_yaml_payload(payload: Mapping[str, Any]) -> dict[str, str]:
    func_name = _normalize_non_empty_text(payload.get("func_name"))
    func_va = _normalize_address_text(payload.get("func_va"))
    disasm_code = _normalize_non_empty_text(payload.get("disasm_code"))
    procedure_raw = payload.get("procedure", "")

    if func_name is None or func_va is None or disasm_code is None:
        raise ReferenceGenerationError("invalid reference YAML payload")

    if procedure_raw is None:
        procedure = ""
    elif isinstance(procedure_raw, str):
        procedure = procedure_raw
    else:
        raise ReferenceGenerationError("invalid reference YAML payload")

    return {
        "func_name": func_name,
        "func_va": func_va,
        "disasm_code": disasm_code,
        "procedure": procedure,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate reference YAML for GoldSrc IDA preprocess scripts")
    parser.add_argument(
        "-gamever",
        default=os.environ.get("GSVIBE_REFERENCE_GAMEVER"),
        help=(
            "GoldSrc game-version tag; defaults to GSVIBE_REFERENCE_GAMEVER, then infers from the "
            "current IDA binary path when unset"
        ),
    )
    parser.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument(
        "-module",
        help="Module name; when omitted, infer it from the current IDA binary path",
    )
    parser.add_argument(
        "-platform",
        choices=["windows", "linux"],
        help="Target platform; when omitted, infer it from the current IDA binary path",
    )
    parser.add_argument("-func_name", required=True, help="Predecessor function name")
    parser.add_argument(
        "-output_filename",
        default=None,
        help="Custom output file name; defaults to <func_name>.<platform>.yaml",
    )
    parser.add_argument("-mcp_host", default="127.0.0.1", help="MCP host")
    parser.add_argument("-mcp_port", type=int, default=13337, help="MCP port")
    parser.add_argument(
        "-mcp_database",
        default=None,
        help="Explicit active MCP database session id",
    )
    parser.add_argument("-ida_args", default="", help="Additional arguments for idalib-mcp")
    parser.add_argument("-debug", action="store_true", help="Enable debug output")
    parser.add_argument("-binary", default=None, help="Binary path for auto-start MCP mode")
    parser.add_argument(
        "-auto_start_mcp",
        action="store_true",
        help="Start an owned IDA MCP lifecycle; must be used with -binary",
    )

    args = parser.parse_args(argv)
    if args.auto_start_mcp and not args.binary:
        parser.error("-auto_start_mcp requires -binary")
    if args.binary and not args.auto_start_mcp:
        parser.error("-binary requires -auto_start_mcp")
    return args


def _safe_path_component(value: Any, label: str) -> str:
    text = _normalize_non_empty_text(value)
    forbidden = '<>:"/\\|?*'
    reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
    if (
        text is None
        or text in {".", ".."}
        or Path(text).name != text
        or any(character in forbidden or ord(character) < 32 for character in text)
        or text.endswith((" ", "."))
        or text.split(".", 1)[0].upper() in reserved
    ):
        raise ReferenceGenerationError(f"{label} must be one safe path component")
    return text


def infer_target_from_binary_path(binary_path: str) -> dict[str, str]:
    normalized_path = _normalize_non_empty_text(binary_path)
    if normalized_path is None:
        raise ReferenceGenerationError("IDA survey did not provide a binary path")

    path_parts = [
        part.strip() for part in normalized_path.replace("\\", "/").split("/") if part.strip() and part != "."
    ]
    bin_index = next(
        (index for index in range(len(path_parts) - 1, -1, -1) if path_parts[index].lower() == "bin"),
        -1,
    )
    if bin_index < 0 or bin_index + 3 >= len(path_parts):
        raise ReferenceGenerationError(
            f"unable to infer -gamever/-module/-platform from IDA binary path: {normalized_path}"
        )

    gamever = path_parts[bin_index + 1]
    module = _safe_path_component(path_parts[bin_index + 2], "module")
    try:
        gamever = validated_tag(gamever)
    except AnalysisConfigError as exc:
        raise ReferenceGenerationError(str(exc)) from exc
    platform = _infer_platform_from_binary_name(path_parts[bin_index + 3])
    if platform is None:
        raise ReferenceGenerationError(f"unable to infer platform from IDA binary path: {normalized_path}")

    return {"gamever": gamever, "module": module, "platform": platform}


def _infer_platform_from_binary_name(binary_name: str) -> str | None:
    suffixes = [suffix.lower() for suffix in Path(binary_name).suffixes]
    if ".dll" in suffixes:
        return "windows"
    if ".so" in suffixes:
        return "linux"
    return None


def validate_autostart_binary(binary_path: str | Path, platform: str | None) -> str:
    try:
        info = inspect_binary(binary_path) if platform is None else validate_binary(binary_path, platform)
    except BinaryFormatError as exc:
        raise ReferenceGenerationError(str(exc)) from exc
    return info.platform


def load_yaml_mapping(path: str | Path) -> dict[str, Any]:
    yaml_path = Path(path)
    if not yaml_path.exists():
        return {}

    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ReferenceGenerationError(f"Failed to parse YAML: {yaml_path}") from exc
    if data is None:
        return {}
    if not isinstance(data, Mapping):
        raise ReferenceGenerationError(f"YAML root must be a mapping: {yaml_path}")
    return dict(data)


def build_reference_output_path(
    repo_root: str | Path,
    gamever: str,
    module: str,
    func_name: str,
    platform: str,
    output_filename: str | None = None,
) -> Path:
    try:
        gamever = validated_tag(gamever)
    except AnalysisConfigError as exc:
        raise ReferenceGenerationError(str(exc)) from exc
    module_name = _safe_path_component(module, "module")
    target_name = _safe_path_component(func_name, "func_name")
    if platform not in {"windows", "linux"}:
        raise ReferenceGenerationError(f"unsupported platform: {platform}")

    if output_filename is None:
        filename = f"{target_name}.{platform}.yaml"
    else:
        filename = _safe_path_component(output_filename, "-output_filename")
    if Path(filename).suffix.lower() != ".yaml":
        raise ReferenceGenerationError("-output_filename must end with .yaml")

    reference_root = Path(repo_root) / "ida_preprocessor_scripts" / "references"
    output_path = reference_root / gamever / module_name / filename
    resolved_root = reference_root.resolve()
    resolved_output = output_path.resolve()
    if not resolved_output.is_relative_to(resolved_root):
        raise ReferenceGenerationError("reference output path escapes the repository reference root")
    return output_path


def build_existing_yaml_path(
    repo_root: str | Path,
    gamever: str,
    module: str,
    func_name: str,
    platform: str,
) -> Path:
    try:
        gamever = validated_tag(gamever)
    except AnalysisConfigError as exc:
        raise ReferenceGenerationError(str(exc)) from exc
    module = _safe_path_component(module, "module")
    func_name = _safe_path_component(func_name, "func_name")
    if platform not in {"windows", "linux"}:
        raise ReferenceGenerationError(f"unsupported platform: {platform}")
    return Path(repo_root) / "bin" / gamever / module / f"{func_name}.{platform}.yaml"


def load_existing_func_va(
    repo_root: str | Path,
    gamever: str,
    module: str,
    func_name: str,
    platform: str,
) -> str | None:
    existing_yaml_path = build_existing_yaml_path(repo_root, gamever, module, func_name, platform)
    existing_yaml_map = load_yaml_mapping(existing_yaml_path)
    if not existing_yaml_map:
        return None
    return _normalize_address_text(existing_yaml_map.get("func_va"))


def load_symbol_aliases(
    config_path: str | Path,
    module: str,
    func_name: str,
) -> list[str]:
    config_map = load_yaml_mapping(config_path)
    modules = config_map.get("modules")
    if not isinstance(modules, list):
        raise ReferenceGenerationError("analysis config missing 'modules' list")

    for module_entry in modules:
        if not isinstance(module_entry, Mapping):
            continue
        module_name = str(module_entry.get("name", "")).strip()
        if module_name != module:
            continue

        symbols = module_entry.get("symbols")
        if not isinstance(symbols, list):
            raise ReferenceGenerationError(f"module '{module}' missing 'symbols' list")
        for symbol_entry in symbols:
            if not isinstance(symbol_entry, Mapping):
                continue
            symbol_name = str(symbol_entry.get("name", "")).strip()
            if symbol_name != func_name:
                continue
            if symbol_entry.get("category") not in {"func", "vfunc"}:
                raise ReferenceGenerationError(f"symbol '{func_name}' in module '{module}' is not a function")

            ordered_aliases: list[str] = []
            seen: set[str] = set()
            raw_alias = symbol_entry.get("alias")
            raw_aliases = raw_alias if isinstance(raw_alias, list) else [raw_alias]
            for raw in [symbol_name, *raw_aliases]:
                if raw is None:
                    continue
                text = str(raw).strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                ordered_aliases.append(text)
            if not ordered_aliases:
                raise ReferenceGenerationError(f"symbol '{func_name}' in module '{module}' has no usable alias values")
            return ordered_aliases

        raise ReferenceGenerationError(f"symbol '{func_name}' not found in module '{module}' within {config_path}")
    raise ReferenceGenerationError(f"module '{module}' not found in {config_path}")


def resolve_configured_binary_path(
    repo_root: str | Path,
    gamever: str,
    module: str,
    platform: str,
    config_path: str | Path,
) -> Path:
    try:
        gamever = validated_tag(gamever)
    except AnalysisConfigError as exc:
        raise ReferenceGenerationError(str(exc)) from exc
    module = _safe_path_component(module, "module")
    if platform not in {"windows", "linux"}:
        raise ReferenceGenerationError(f"unsupported platform: {platform}")

    config_map = load_yaml_mapping(config_path)
    modules = config_map.get("modules")
    if not isinstance(modules, list):
        raise ReferenceGenerationError("analysis config missing 'modules' list")
    for module_entry in modules:
        if not isinstance(module_entry, Mapping) or str(module_entry.get("name", "")).strip() != module:
            continue
        binary_name = _normalize_non_empty_text(module_entry.get(f"module_{platform}"))
        if binary_name is None:
            source_path = _normalize_non_empty_text(module_entry.get(f"path_{platform}"))
            if source_path is not None:
                binary_name = source_path.replace("\\", "/").rsplit("/", 1)[-1]
        if binary_name is None:
            raise ReferenceGenerationError(f"module '{module}' does not declare a {platform} binary in {config_path}")
        binary_name = _safe_path_component(binary_name, f"module_{platform}")
        return Path(repo_root) / "bin" / gamever / module / binary_name
    raise ReferenceGenerationError(f"module '{module}' not found in {config_path}")


def _parse_py_eval_json_result(eval_result: Any, *, debug: bool = False) -> Any:
    parsed = parse_mcp_result(eval_result)
    if isinstance(parsed, Mapping) and ("result" in parsed or "stderr" in parsed):
        stderr_text = str(parsed.get("stderr", "")).strip()
        if stderr_text and debug:
            print(f"py_eval stderr: {stderr_text}")
        result_value = parsed.get("result")
        if result_value is None or result_value == "":
            raise ReferenceGenerationError("missing py_eval result from IDA")
        parsed = result_value

    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError as exc:
            raise ReferenceGenerationError("invalid py_eval JSON payload from IDA") from exc
    if not isinstance(parsed, (Mapping, list)):
        raise ReferenceGenerationError("invalid py_eval response from IDA")
    return parsed


async def find_function_addr_by_names(
    session: Any,
    candidate_names: Sequence[str],
    *,
    debug: bool = False,
) -> str:
    ordered_candidates: list[str] = []
    seen_candidates: set[str] = set()
    for raw_name in candidate_names:
        text = str(raw_name).strip()
        if not text or text in seen_candidates:
            continue
        seen_candidates.add(text)
        ordered_candidates.append(text)
    if not ordered_candidates:
        raise ReferenceGenerationError("unable to locate function address via IDA")

    py_code = (
        "import ida_funcs, ida_name, idaapi, json\n"
        f"candidate_names = {json.dumps(ordered_candidates)}\n"
        "matches = []\n"
        "seen_addrs = set()\n"
        "for candidate_name in candidate_names:\n"
        "    ea = ida_name.get_name_ea(idaapi.BADADDR, candidate_name)\n"
        "    if ea == idaapi.BADADDR:\n"
        "        continue\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is None:\n"
        "        continue\n"
        "    func_start = int(func.start_ea)\n"
        "    func_va = hex(func_start)\n"
        "    if func_va in seen_addrs:\n"
        "        continue\n"
        "    seen_addrs.add(func_va)\n"
        "    matches.append({'name': candidate_name, 'func_va': func_va})\n"
        "result = json.dumps(matches)\n"
    )
    try:
        eval_result = await session.call_tool(name="py_eval", arguments={"code": py_code})
        match_payload = _parse_py_eval_json_result(eval_result, debug=debug)
    except ReferenceGenerationError:
        raise
    except Exception as exc:
        raise ReferenceGenerationError("unable to locate function address via IDA") from exc
    if not isinstance(match_payload, list):
        raise ReferenceGenerationError("unable to locate function address via IDA")

    resolved_matches: list[str] = []
    seen_func_vas: set[str] = set()
    for item in match_payload:
        if not isinstance(item, Mapping):
            continue
        func_va = _normalize_address_text(item.get("func_va"))
        if func_va is None or func_va in seen_func_vas:
            continue
        seen_func_vas.add(func_va)
        resolved_matches.append(func_va)
    if not resolved_matches:
        raise ReferenceGenerationError("unable to locate function address via IDA")
    if len(resolved_matches) > 1:
        raise ReferenceGenerationError(f"ambiguous function address matches returned via IDA: {resolved_matches!r}")
    return resolved_matches[0]


async def resolve_func_va(
    session: Any,
    *,
    repo_root: str | Path,
    gamever: str,
    module: str,
    platform: str,
    func_name: str,
    config_path: str | Path,
    debug: bool,
) -> str:
    existing_func_va = load_existing_func_va(repo_root, gamever, module, func_name, platform)
    if existing_func_va:
        return existing_func_va
    candidate_names = load_symbol_aliases(config_path, module, func_name)
    return await find_function_addr_by_names(session, candidate_names, debug=debug)


async def export_reference_payload_via_mcp(
    session: Any,
    *,
    func_name: str,
    func_va: str,
    debug: bool = False,
) -> dict[str, str]:
    normalized_input_func_va = _normalize_address_text(func_va)
    if normalized_input_func_va is None:
        raise ReferenceGenerationError("unable to export reference payload via IDA")
    try:
        py_code = build_function_detail_export_py_eval(int(normalized_input_func_va, 0))
        eval_result = await session.call_tool(name="py_eval", arguments={"code": py_code})
        exported_payload = _parse_py_eval_json_result(eval_result, debug=debug)
    except ReferenceGenerationError:
        raise
    except Exception as exc:
        raise ReferenceGenerationError("unable to export reference payload via IDA") from exc
    if not isinstance(exported_payload, Mapping):
        raise ReferenceGenerationError("unable to export reference payload via IDA")

    return _validate_reference_yaml_payload(
        {
            "func_name": func_name,
            "func_va": exported_payload.get("func_va"),
            "disasm_code": exported_payload.get("disasm_code"),
            "procedure": exported_payload.get("procedure", ""),
        }
    )


def build_reference_yaml_export_py_eval(
    func_va_int: int,
    *,
    output_path: str | Path,
    func_name: str,
) -> str:
    normalized_func_name = str(func_name).strip()
    producer_code = (
        build_function_detail_export_py_eval(func_va_int).rstrip()
        + "\n"
        + "payload = json.loads(result)\n"
        + f"expected_func_va = {func_va_int}\n"
        + "resolved_func_va = int(str(payload.get('func_va', '')), 0)\n"
        + "if resolved_func_va != expected_func_va:\n"
        + "    raise ValueError(\n"
        + "        f'function start mismatch: expected {hex(expected_func_va)}, got {hex(resolved_func_va)}'\n"
        + "    )\n"
        + "disasm_code = payload.get('disasm_code')\n"
        + "procedure = payload.get('procedure', '')\n"
        + "if not isinstance(disasm_code, str) or not disasm_code.strip():\n"
        + "    raise ValueError('reference disassembly is empty')\n"
        + "if procedure is None:\n"
        + "    procedure = ''\n"
        + "if not isinstance(procedure, str):\n"
        + "    raise ValueError('reference procedure is not text')\n"
        + "if not 0 <= resolved_func_va <= 0xFFFFFFFF:\n"
        + "    raise ValueError('reference function address is outside x86 range')\n"
        + f"canonical_func_name = {json.dumps(normalized_func_name)}\n"
        + "if not canonical_func_name:\n"
        + "    raise ValueError('reference function name is empty')\n"
        + "def _yaml_scalar(value):\n"
        + "    return json.dumps(str(value), ensure_ascii=False)\n"
        + "def _yaml_text_field(name, value):\n"
        + "    normalized = value.replace('\\r\\n', '\\n').replace('\\r', '\\n')\n"
        + "    if not normalized:\n"
        + "        return name + \": ''\\n\"\n"
        + "    body = '\\n'.join('  ' + line for line in normalized.split('\\n'))\n"
        + "    return name + ': |-\\n' + body + '\\n'\n"
        + "payload_text = (\n"
        + "    'func_name: ' + _yaml_scalar(canonical_func_name) + '\\n'\n"
        + "    + 'func_va: ' + _yaml_scalar(hex(resolved_func_va)) + '\\n'\n"
        + "    + _yaml_text_field('disasm_code', disasm_code)\n"
        + "    + _yaml_text_field('procedure', procedure)\n"
        + ")\n"
    )
    return build_remote_text_export_py_eval(
        output_path=output_path,
        producer_code=producer_code,
        content_var="payload_text",
        format_name="yaml",
    )


def _is_valid_remote_export_ack(
    export_ack: Any,
    *,
    output_path: str | Path,
    format_name: str,
) -> bool:
    if not isinstance(export_ack, Mapping) or not bool(export_ack.get("ok")):
        return False
    if str(export_ack.get("output_path", "")).strip() != os.fspath(output_path):
        return False
    if str(export_ack.get("format", "")).strip() != format_name:
        return False
    try:
        bytes_written = int(export_ack.get("bytes_written"))
    except (TypeError, ValueError):
        return False
    return bytes_written >= 0


async def export_reference_yaml_via_mcp(
    session: Any,
    *,
    func_name: str,
    func_va: str,
    output_path: str | Path,
    debug: bool = False,
) -> Path:
    normalized_input_func_va = _normalize_address_text(func_va)
    if normalized_input_func_va is None:
        raise ReferenceGenerationError("unable to export reference YAML via IDA")
    resolved_output_path = Path(output_path).resolve()
    try:
        py_code = build_reference_yaml_export_py_eval(
            int(normalized_input_func_va, 0),
            output_path=resolved_output_path,
            func_name=func_name,
        )
        eval_result = await session.call_tool(name="py_eval", arguments={"code": py_code})
        export_ack = _parse_py_eval_json_result(eval_result, debug=debug)
    except ReferenceGenerationError:
        raise
    except Exception as exc:
        raise ReferenceGenerationError("unable to export reference YAML via IDA") from exc
    if not _is_valid_remote_export_ack(export_ack, output_path=resolved_output_path, format_name="yaml"):
        detail = ""
        if isinstance(export_ack, Mapping) and export_ack.get("error"):
            detail = f": {str(export_ack['error']).strip()}"
        raise ReferenceGenerationError(f"unable to export reference YAML via IDA{detail}")

    try:
        payload = yaml.safe_load(resolved_output_path.read_text(encoding="utf-8")) or {}
        if not isinstance(payload, Mapping) or set(payload) != REFERENCE_YAML_FIELDS:
            raise ReferenceGenerationError("invalid reference YAML schema")
        validated_payload = _validate_reference_yaml_payload(payload)
        if validated_payload["func_name"] != func_name or int(validated_payload["func_va"], 0) != int(
            normalized_input_func_va, 0
        ):
            raise ReferenceGenerationError("reference YAML identity does not match the requested function")
    except Exception as exc:
        raise ReferenceGenerationError("unable to export reference YAML via IDA") from exc
    return resolved_output_path


def write_reference_yaml(path: str | Path, payload: Mapping[str, Any]) -> None:
    minimal_payload = _validate_reference_yaml_payload(payload)
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.dump(
            minimal_payload,
            Dumper=LiteralDumper,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )


def _load_ida_analyze_bin() -> Any:
    try:
        return importlib.import_module("ida_analyze_bin")
    except (ImportError, SystemExit) as exc:
        raise ReferenceGenerationError("failed to import ida_analyze_bin helpers") from exc


async def survey_binary_via_session(session: Any) -> Any:
    ida_analyze_bin = _load_ida_analyze_bin()
    return await ida_analyze_bin.survey_binary_via_session(session, detail_level="minimal")


async def validate_bound_binary_via_session(
    session: Any,
    binary_path: str | Path,
    platform: str,
) -> None:
    survey_payload = await survey_binary_via_session(session)
    ida_analyze_bin = _load_ida_analyze_bin()
    try:
        valid, reasons = ida_analyze_bin.validate_opened_binary_identity(binary_path, platform, survey_payload)
    except Exception as exc:
        raise ReferenceGenerationError(f"unable to validate the bound IDA database for {binary_path}: {exc}") from exc
    if not valid:
        detail = "; ".join(str(reason) for reason in reasons) or "unknown identity mismatch"
        raise ReferenceGenerationError(f"bound IDA database does not match {binary_path}: {detail}")


def create_ida_mcp_lifecycle(
    binary_path: str,
    platform: str,
    host: str,
    port: int,
    ida_args: str,
    debug: bool,
) -> Any:
    ida_analyze_bin = _load_ida_analyze_bin()
    return ida_analyze_bin.IdaMcpLifecycle(binary_path, platform, host, port, ida_args, debug)


@asynccontextmanager
async def attach_existing_mcp_session(
    host: str,
    port: int,
    debug: bool,
    *,
    expected_binary: str | None = None,
    explicit_database: str | None = None,
):
    del debug
    session_kwargs = {}
    if expected_binary is not None:
        session_kwargs["expected_binary"] = expected_binary
    if explicit_database is not None:
        session_kwargs["explicit_database"] = explicit_database
    try:
        async with open_ida_mcp_session(host, port, **session_kwargs) as session:
            yield session
    except (McpConnectionError, McpDatabaseSelectionError, McpToolCallError) as exc:
        raise ReferenceGenerationError(str(exc)) from exc


@asynccontextmanager
async def autostart_mcp_session(
    binary_path: str,
    platform: str,
    host: str,
    port: int,
    ida_args: str,
    debug: bool,
    *,
    explicit_database: str | None = None,
):
    lifecycle = create_ida_mcp_lifecycle(binary_path, platform, host, port, ida_args, debug)
    entered = False
    try:
        startup_task = asyncio.create_task(asyncio.to_thread(lifecycle.__enter__))
        try:
            await asyncio.shield(startup_task)
            entered = True
        except asyncio.CancelledError:
            startup_result = await asyncio.gather(startup_task, return_exceptions=True)
            entered = not isinstance(startup_result[0], BaseException)
            raise
        except Exception as exc:
            raise ReferenceGenerationError(f"failed to start IDA MCP lifecycle for {binary_path}: {exc}") from exc

        session_kwargs = {
            "expected_binary": binary_path,
            "auto_started": True,
        }
        if explicit_database is not None:
            session_kwargs["explicit_database"] = explicit_database
        try:
            async with open_ida_mcp_session(host, port, **session_kwargs) as session:
                yield session
        except (McpConnectionError, McpDatabaseSelectionError, McpToolCallError) as exc:
            raise ReferenceGenerationError(str(exc)) from exc
    finally:
        if entered:
            try:
                await asyncio.to_thread(lifecycle.__exit__, None, None, None)
            except Exception as exc:
                raise ReferenceGenerationError(f"failed to stop IDA MCP lifecycle for {binary_path}: {exc}") from exc


def _normalize_explicit_target(
    gamever: str | None,
    module: str | None,
    platform: str | None,
) -> dict[str, str | None]:
    resolved_gamever = _normalize_non_empty_text(gamever)
    if resolved_gamever is not None:
        try:
            resolved_gamever = validated_tag(resolved_gamever)
        except AnalysisConfigError as exc:
            raise ReferenceGenerationError(str(exc)) from exc
    resolved_module = _normalize_non_empty_text(module)
    if resolved_module is not None:
        resolved_module = _safe_path_component(resolved_module, "module")
    resolved_platform = _normalize_non_empty_text(platform)
    if resolved_platform is not None and resolved_platform not in {"windows", "linux"}:
        raise ReferenceGenerationError(f"unsupported platform: {resolved_platform}")
    return {
        "gamever": resolved_gamever,
        "module": resolved_module,
        "platform": resolved_platform,
    }


def _require_configured_binary(requested_binary: str | Path, configured_binary: str | Path) -> None:
    requested = normalize_binary_identity_path(Path(requested_binary).resolve())
    configured = normalize_binary_identity_path(Path(configured_binary).resolve())
    if requested != configured:
        raise ReferenceGenerationError(
            f"-binary must match the configured target binary: requested {requested_binary}, expected {configured_binary}"
        )


async def resolve_generation_target(
    *,
    session: Any,
    gamever: str | None,
    module: str | None,
    platform: str | None,
) -> dict[str, str]:
    resolved_target = _normalize_explicit_target(gamever, module, platform)
    missing_keys = [key for key, value in resolved_target.items() if value is None]
    if missing_keys:
        survey_result = await survey_binary_via_session(session)
        if not isinstance(survey_result, Mapping):
            missing_flags = ", ".join(f"-{key}" for key in missing_keys)
            raise ReferenceGenerationError(
                f"missing {missing_flags}, and failed to survey the current IDA binary via MCP"
            )
        metadata = survey_result.get("metadata")
        if not isinstance(metadata, Mapping):
            raise ReferenceGenerationError("IDA survey result is missing metadata")
        inferred_target = infer_target_from_binary_path(str(metadata.get("path", "")))
        for key in missing_keys:
            resolved_target[key] = inferred_target[key]
    return {
        "gamever": str(resolved_target["gamever"]),
        "module": str(resolved_target["module"]),
        "platform": str(resolved_target["platform"]),
    }


async def run_reference_generation(
    args: argparse.Namespace,
    repo_root: str | Path | None = None,
) -> Path:
    resolved_repo_root = Path(repo_root) if repo_root is not None else Path(__file__).resolve().parent
    func_name = _safe_path_component(args.func_name, "func_name")

    explicit_target = _normalize_explicit_target(args.gamever, args.module, args.platform)
    resolved_target_before_session = None
    config_path = None
    configured_binary = None
    if all(explicit_target.values()):
        resolved_target_before_session = {key: str(value) for key, value in explicit_target.items()}
        try:
            config_path = resolve_analysis_config(
                resolved_target_before_session["gamever"],
                getattr(args, "configyaml", None),
                repo_root=resolved_repo_root,
            )
        except AnalysisConfigError as exc:
            raise ReferenceGenerationError(str(exc)) from exc
        configured_binary = resolve_configured_binary_path(
            resolved_repo_root,
            resolved_target_before_session["gamever"],
            resolved_target_before_session["module"],
            resolved_target_before_session["platform"],
            config_path,
        )
        validate_autostart_binary(configured_binary, resolved_target_before_session["platform"])

    autostart_platform = None
    if args.auto_start_mcp:
        autostart_platform = validate_autostart_binary(args.binary, args.platform)
        if configured_binary is not None:
            _require_configured_binary(args.binary, configured_binary)
        session_kwargs = {
            "binary_path": args.binary,
            "platform": autostart_platform,
            "host": args.mcp_host,
            "port": args.mcp_port,
            "ida_args": args.ida_args,
            "debug": args.debug,
        }
        if args.mcp_database is not None:
            session_kwargs["explicit_database"] = args.mcp_database
        session_manager = autostart_mcp_session(**session_kwargs)
    else:
        session_kwargs = {
            "host": args.mcp_host,
            "port": args.mcp_port,
            "debug": args.debug,
        }
        if configured_binary is not None:
            session_kwargs["expected_binary"] = os.fspath(configured_binary)
        if args.mcp_database is not None:
            session_kwargs["explicit_database"] = args.mcp_database
        session_manager = attach_existing_mcp_session(**session_kwargs)

    async with session_manager as session:
        resolved_target = await resolve_generation_target(
            session=session,
            gamever=args.gamever,
            module=args.module,
            platform=args.platform or autostart_platform,
        )
        if config_path is None:
            try:
                config_path = resolve_analysis_config(
                    resolved_target["gamever"],
                    getattr(args, "configyaml", None),
                    repo_root=resolved_repo_root,
                )
            except AnalysisConfigError as exc:
                raise ReferenceGenerationError(str(exc)) from exc
        print(f"Analysis config: {config_path}")
        if configured_binary is None:
            configured_binary = resolve_configured_binary_path(
                resolved_repo_root,
                resolved_target["gamever"],
                resolved_target["module"],
                resolved_target["platform"],
                config_path,
            )
            validate_autostart_binary(configured_binary, resolved_target["platform"])
        if args.auto_start_mcp:
            _require_configured_binary(args.binary, configured_binary)
        await validate_bound_binary_via_session(
            session,
            configured_binary,
            resolved_target["platform"],
        )
        func_va = await resolve_func_va(
            session,
            repo_root=resolved_repo_root,
            gamever=resolved_target["gamever"],
            module=resolved_target["module"],
            platform=resolved_target["platform"],
            func_name=func_name,
            config_path=config_path,
            debug=args.debug,
        )
        output_path = build_reference_output_path(
            resolved_repo_root,
            resolved_target["gamever"],
            resolved_target["module"],
            func_name,
            resolved_target["platform"],
            args.output_filename,
        )
        return await export_reference_yaml_via_mcp(
            session,
            func_name=func_name,
            func_va=func_va,
            output_path=output_path,
            debug=args.debug,
        )


def main(argv: Sequence[str] | None = None) -> int:
    load_dotenv(Path(__file__).with_name(".env"))
    args = parse_args(argv)
    try:
        output_path = asyncio.run(run_reference_generation(args))
    except ReferenceGenerationError as exc:
        print(f"ERROR: {exc}")
        return 1
    print(f"Generated reference YAML: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
