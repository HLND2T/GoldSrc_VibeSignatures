"""Architecture-neutral artifact helpers and x86 global-reference resolution."""

from __future__ import annotations

import json
import math
import os
import re
import textwrap
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path

import yaml

from analysis_config import validated_tag
from ida_llm_decompile import (
    _build_llm_decompile_request_cache_key,
    _empty_llm_decompile_result,
    call_llm_decompile,
    render_llm_decompile_blocks,
)

SYMBOL_CATEGORIES = frozenset({"func", "gv", "vfunc", "vtable", "patch", "structmember"})
SIGNATURE_RE = re.compile(r"^(?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?))*$")
LEGACY_ARTIFACT_FIELDS = frozenset({"name", "type", "kind"})
CATEGORY_IDENTITY_FIELDS = {
    "func": ("func_name",),
    "vfunc": ("func_name",),
    "gv": ("gv_name",),
    "patch": ("patch_name",),
    "vtable": ("vtable_class",),
    "structmember": ("struct_name", "member_name"),
}

FUNC_YAML_ORDER = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "func_sig_allow_across_function_boundary",
    "func_sig_resolve_jmp_thunk",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
    "vfunc_sig",
    "vfunc_sig_max_match",
    "vfunc_sig_allow_across_function_boundary",
]
GV_YAML_ORDER = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary",
]
VTABLE_YAML_ORDER = [
    "vtable_class",
    "vtable_symbol",
    "vtable_va",
    "vtable_rva",
    "vtable_size",
    "vtable_numvfunc",
    "vtable_entries",
]
PATCH_YAML_ORDER = ["patch_name", "patch_va", "patch_rva", "patch_sig", "patch_sig_disp", "patch_bytes"]
STRUCT_MEMBER_YAML_ORDER = [
    "struct_name",
    "member_name",
    "offset",
    "size",
    "offset_sig",
    "offset_sig_disp",
    "offset_sig_max_match",
    "offset_sig_allow_across_function_boundary",
]
CATEGORY_FIELD_ORDER = {
    "func": FUNC_YAML_ORDER,
    "vfunc": FUNC_YAML_ORDER,
    "gv": GV_YAML_ORDER,
    "vtable": VTABLE_YAML_ORDER,
    "patch": PATCH_YAML_ORDER,
    "structmember": STRUCT_MEMBER_YAML_ORDER,
}
FUNC_XREF_ALLOWED_KEYS = frozenset(
    {
        "func_name",
        "xref_strings",
        "xref_gvs",
        "xref_signatures",
        "xref_funcs",
        "inline_alias",
        "xref_floats",
        "exclude_funcs",
        "exclude_strings",
        "exclude_gvs",
        "exclude_signatures",
        "exclude_floats",
        "exclude_callees",
    }
)
FUNC_XREF_LIST_KEYS = tuple(FUNC_XREF_ALLOWED_KEYS - {"func_name", "inline_alias"})
DEFAULT_IDA_STRING_MIN_LENGTH = 4
IDA_STRING_MIN_LENGTH_ENV_VAR = "GSVIBE_STRING_MIN_LENGTH"
IDA_STRING_SETUP_STATE_NODE = "$GSVIBE_STRING_SETUP_STATE"
IDA_STRING_SETUP_STATE_VERSION = 1


def _coerce_ida_string_min_length(value):
    try:
        min_length = int(str(value).strip())
    except (TypeError, ValueError):
        return DEFAULT_IDA_STRING_MIN_LENGTH
    return min_length if min_length >= 1 else DEFAULT_IDA_STRING_MIN_LENGTH


def _resolve_ida_string_min_length_config():
    raw_min_length = os.getenv(IDA_STRING_MIN_LENGTH_ENV_VAR)
    if raw_min_length is None or not str(raw_min_length).strip():
        return None
    return _coerce_ida_string_min_length(raw_min_length)


class SymbolArtifactError(ValueError):
    pass


def quoted_hex(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SymbolArtifactError(f"Expected a non-negative integer, got {value!r}")
    return f"0x{value:x}"


def normalize_signature(value: str | bytes | Iterable[int | None]) -> str:
    if isinstance(value, bytes):
        tokens = [f"{byte:02X}" for byte in value]
    elif isinstance(value, str):
        raw = value.strip().replace("\\x", " ").replace(",", " ").replace("*", "?")
        tokens = raw.split()
        normalized = []
        for token in tokens:
            token = token.upper()
            if token in {"?", "??"} or "?" in token:
                normalized.append("??")
            elif re.fullmatch(r"[0-9A-F]{2}", token):
                normalized.append(token)
            else:
                raise SymbolArtifactError(f"Invalid signature token: {token!r}")
        tokens = normalized
    else:
        tokens = ["??" if byte is None else f"{byte:02X}" for byte in value]
    signature = " ".join(tokens)
    if not signature or not SIGNATURE_RE.fullmatch(signature):
        raise SymbolArtifactError(f"Invalid signature: {value!r}")
    return signature


def signature_matches(data: bytes, signature: str) -> list[int]:
    tokens = normalize_signature(signature).split()
    pattern = [None if token == "??" else int(token, 16) for token in tokens]
    if len(pattern) > len(data):
        return []
    return [
        offset
        for offset in range(len(data) - len(pattern) + 1)
        if all(expected is None or data[offset + index] == expected for index, expected in enumerate(pattern))
    ]


def _parse_int(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise SymbolArtifactError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise SymbolArtifactError(f"{field} must be an integer") from exc
    raise SymbolArtifactError(f"{field} must be an integer")


def resolve_x86_global_reference(
    *,
    operands: Iterable[int | Mapping[str, object]] = (),
    data_xrefs: Iterable[int] = (),
    gv_ref_kind: str = "operand",
    gv_ref_index: int = 0,
    gv_ref_deref_count: int = 0,
    read_u32: Callable[[int], int | bytes] | None = None,
) -> int:
    if gv_ref_kind not in {"operand", "data_xref"}:
        raise SymbolArtifactError("gv_ref_kind must be operand or data_xref")
    if isinstance(gv_ref_index, bool) or not isinstance(gv_ref_index, int) or gv_ref_index < 0:
        raise SymbolArtifactError("gv_ref_index must be a non-negative integer")
    if gv_ref_deref_count not in {0, 1, 2}:
        raise SymbolArtifactError("gv_ref_deref_count must be between 0 and 2")
    if gv_ref_kind == "operand":
        candidates = list(operands)
        if gv_ref_index >= len(candidates):
            raise SymbolArtifactError("gv_ref_index is outside the instruction operands")
        selected = candidates[gv_ref_index]
        if isinstance(selected, Mapping):
            selected = selected.get("address", selected.get("value"))
        address = _parse_int(selected, "operand reference")
    else:
        candidates = sorted({_parse_int(value, "data xref") for value in data_xrefs})
        if gv_ref_index >= len(candidates):
            raise SymbolArtifactError("gv_ref_index is outside the sorted data xrefs")
        address = candidates[gv_ref_index]
    for _ in range(gv_ref_deref_count):
        if read_u32 is None:
            raise SymbolArtifactError("read_u32 is required when gv_ref_deref_count is non-zero")
        value = read_u32(address)
        if isinstance(value, bytes):
            if len(value) != 4:
                raise SymbolArtifactError("read_u32 returned a byte string whose length is not 4")
            address = int.from_bytes(value, "little")
        else:
            address = _parse_int(value, "dereferenced value")
    return address


def _infer_artifact_category(payload: Mapping[str, object]) -> str:
    candidates: set[str] = set()
    if "func_name" in payload:
        candidates.add("vfunc" if any(key.startswith("vfunc_") or key == "vtable_name" for key in payload) else "func")
    if "gv_name" in payload:
        candidates.add("gv")
    if "patch_name" in payload:
        candidates.add("patch")
    if "vtable_class" in payload:
        candidates.add("vtable")
    if "struct_name" in payload or "member_name" in payload:
        candidates.add("structmember")
    if len(candidates) != 1:
        raise SymbolArtifactError(f"Unable to infer one symbol category from artifact identities: {sorted(candidates)}")
    return candidates.pop()


def normalize_symbol_artifact(payload: Mapping[str, object], *, category: str | None = None) -> dict:
    if not isinstance(payload, Mapping):
        raise SymbolArtifactError("Symbol artifact must be a mapping")
    legacy = sorted(LEGACY_ARTIFACT_FIELDS.intersection(payload))
    if legacy:
        raise SymbolArtifactError(f"Legacy artifact fields are not accepted: {', '.join(legacy)}")
    category = category or _infer_artifact_category(payload)
    if category not in SYMBOL_CATEGORIES:
        raise SymbolArtifactError(f"Unsupported symbol category: {category!r}")
    for identity_field in CATEGORY_IDENTITY_FIELDS[category]:
        value = payload.get(identity_field)
        if not isinstance(value, str) or not value.strip():
            raise SymbolArtifactError(f"{category} artifact requires non-empty {identity_field}")
    normalized = dict(payload)
    for field, value in tuple(normalized.items()):
        if field.endswith("_sig") and value is not None:
            normalized[field] = normalize_signature(value)
        if field.endswith(("_addr", "_va", "_rva", "_size", "_offset", "_length", "_disp")) and value is not None:
            normalized[field] = quoted_hex(_parse_int(value, field))
    if category == "vfunc":
        if "vfunc_slot_size" in normalized and _parse_int(normalized["vfunc_slot_size"], "vfunc_slot_size") != 4:
            raise SymbolArtifactError("GoldSrc x86 vfunc slots are exactly 4 bytes")
        if "vfunc_offset" in normalized:
            offset = _parse_int(normalized["vfunc_offset"], "vfunc_offset")
            if offset % 4:
                raise SymbolArtifactError("GoldSrc x86 vfunc_offset must be 4-byte aligned")
            if "vfunc_index" in normalized and _parse_int(normalized["vfunc_index"], "vfunc_index") != offset // 4:
                raise SymbolArtifactError("vfunc_index does not match vfunc_offset / 4")
    return normalized


def _ordered_payload(payload: Mapping[str, object], category: str) -> dict:
    ordered = {}
    for key in CATEGORY_FIELD_ORDER[category]:
        if key not in payload:
            continue
        if key == "vtable_entries" and isinstance(payload[key], Mapping):
            ordered[key] = dict(sorted((int(index), str(value)) for index, value in payload[key].items()))
        else:
            ordered[key] = payload[key]
    for key, value in payload.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def write_symbol_yaml(path: str | Path, payload: Mapping[str, object], *, category: str | None = None) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    category = category or _infer_artifact_category(payload)
    normalized = normalize_symbol_artifact(payload, category=category)
    target.write_text(
        yaml.safe_dump(_ordered_payload(normalized, category), allow_unicode=True, sort_keys=False, width=120),
        encoding="utf-8",
        newline="\n",
    )


def write_func_yaml(path, data):
    category = "vfunc" if any(key.startswith("vfunc_") or key == "vtable_name" for key in data) else "func"
    write_symbol_yaml(path, data, category=category)


def write_gv_yaml(path, data):
    write_symbol_yaml(path, data, category="gv")


def write_patch_yaml(path, data):
    write_symbol_yaml(path, data, category="patch")


def write_vtable_yaml(path, data):
    write_symbol_yaml(path, data, category="vtable")


def write_struct_offset_yaml(path, data):
    write_symbol_yaml(path, data, category="structmember")


def parse_mcp_result(result):
    """Extract a JSON-compatible value from MCP structured or text content."""

    if isinstance(result, (dict, list, str, int, float, bool)) or result is None:
        value = result
    else:
        structured = getattr(result, "structuredContent", None)
        if not isinstance(structured, dict):
            structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict):
            value = structured.get("result", structured)
        else:
            content = getattr(result, "content", None) or []
            value = getattr(content[0], "text", None) if content else None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _is_remote_absolute_path(path):
    """Accept absolute paths using either the local or remote host path syntax."""
    import ntpath
    import posixpath

    value = os.fspath(path)
    return os.path.isabs(value) or posixpath.isabs(value) or ntpath.isabs(value)


def build_remote_text_export_py_eval(
    *,
    output_path,
    producer_code,
    content_var="payload_text",
    format_name="text",
):
    """Build a py_eval script that writes large text atomically and returns a small ack."""
    output_path_str = os.fspath(output_path)
    if not _is_remote_absolute_path(output_path_str):
        raise ValueError(f"output_path must be absolute, got {output_path_str!r}")
    if not str(producer_code).strip():
        raise ValueError("producer_code cannot be empty")
    if not str(content_var).strip():
        raise ValueError("content_var cannot be empty")

    producer_block = textwrap.indent(str(producer_code).rstrip(), "    ")
    return (
        "import json, ntpath, os, posixpath, traceback\n"
        f"output_path = {output_path_str!r}\n"
        f"format_name = {str(format_name)!r}\n"
        "tmp_path = output_path + '.tmp'\n"
        "def _is_remote_absolute_path(output_path, _os=os, _posixpath=posixpath, _ntpath=ntpath):\n"
        "    return (\n"
        "        _os.path.isabs(output_path)\n"
        "        or _posixpath.isabs(output_path)\n"
        "        or _ntpath.isabs(output_path)\n"
        "    )\n"
        "def _truncate_text(value, limit=800):\n"
        "    text = '' if value is None else str(value)\n"
        "    return text if len(text) <= limit else text[:limit] + ' [truncated]'\n"
        "try:\n"
        "    if not _is_remote_absolute_path(output_path):\n"
        "        raise ValueError(f'output_path must be absolute: {output_path}')\n"
        f"{producer_block}\n"
        f"    payload_text = str({content_var})\n"
        "    parent_dir = os.path.dirname(output_path)\n"
        "    if parent_dir:\n"
        "        os.makedirs(parent_dir, exist_ok=True)\n"
        "    with open(tmp_path, 'w', encoding='utf-8') as handle:\n"
        "        handle.write(payload_text)\n"
        "    os.replace(tmp_path, output_path)\n"
        "    result = json.dumps({\n"
        "        'ok': True,\n"
        "        'output_path': output_path,\n"
        "        'bytes_written': len(payload_text.encode('utf-8')),\n"
        "        'format': format_name,\n"
        "    })\n"
        "except Exception as exc:\n"
        "    try:\n"
        "        if os.path.exists(tmp_path):\n"
        "            os.unlink(tmp_path)\n"
        "    except Exception:\n"
        "        pass\n"
        "    result = json.dumps({\n"
        "        'ok': False,\n"
        "        'output_path': output_path,\n"
        "        'error': _truncate_text(exc),\n"
        "        'traceback': _truncate_text(traceback.format_exc()),\n"
        "    })\n"
    )


def build_function_detail_export_py_eval(func_va_int: int) -> str:
    """Build a robust function-detail export script for reference YAML generation."""
    return (
        textwrap.dedent(
            rf"""
        import ida_bytes, ida_funcs, ida_lines, ida_segment, idautils, idc, json
        try:
            import ida_hexrays
        except Exception:
            ida_hexrays = None

        func_ea = {func_va_int}

        def _append_chunk_range(chunk_ranges, start_ea, end_ea):
            try:
                start_ea = int(start_ea)
                end_ea = int(end_ea)
            except Exception:
                return
            if start_ea < end_ea:
                chunk_ranges.append((start_ea, end_ea))

        def _collect_chunk_ranges(func):
            chunk_ranges = []
            try:
                initial_chunk_ranges = []
                for start_ea, end_ea in idautils.Chunks(func.start_ea):
                    _append_chunk_range(initial_chunk_ranges, start_ea, end_ea)
                chunk_ranges = initial_chunk_ranges
            except Exception:
                pass
            if not chunk_ranges:
                tail_chunk_ranges = []
                try:
                    try:
                        tail_iterator = ida_funcs.func_tail_iterator_t(func)
                    except Exception:
                        tail_iterator = ida_funcs.func_tail_iterator_t()
                        if not tail_iterator.set_ea(func.start_ea):
                            tail_iterator = None
                    if tail_iterator is not None and tail_iterator.first():
                        while True:
                            chunk = tail_iterator.chunk()
                            _append_chunk_range(
                                tail_chunk_ranges,
                                getattr(chunk, 'start_ea', None),
                                getattr(chunk, 'end_ea', None),
                            )
                            if not tail_iterator.next():
                                break
                except Exception:
                    tail_chunk_ranges = []
                if tail_chunk_ranges:
                    _append_chunk_range(
                        tail_chunk_ranges,
                        func.start_ea,
                        func.end_ea,
                    )
                    chunk_ranges = tail_chunk_ranges
            if not chunk_ranges:
                chunk_ranges = [(int(func.start_ea), int(func.end_ea))]
            return sorted(set(chunk_ranges))

        def _find_chunk_end(ea, chunk_ranges):
            for start_ea, end_ea in chunk_ranges:
                if start_ea <= ea < end_ea:
                    return end_ea
            return None

        def _is_in_chunk_ranges(ea, chunk_ranges):
            return _find_chunk_end(ea, chunk_ranges) is not None

        def _format_address(ea):
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else ''
            return f"{{seg_name}}:{{ea:08X}}" if seg_name else f"{{ea:08X}}"

        def _iter_comment_lines(ea):
            seen = set()
            for repeatable in (0, 1):
                try:
                    comment = idc.get_cmt(ea, repeatable)
                except Exception:
                    comment = None
                if not comment:
                    continue
                text = ida_lines.tag_remove(comment).strip()
                if text and text not in seen:
                    seen.add(text)
                    yield text

            get_extra_cmt = getattr(idc, 'get_extra_cmt', None)
            if get_extra_cmt is None:
                return
            for constant_name in ('E_PREV', 'E_NEXT'):
                base_index = getattr(ida_lines, constant_name, None)
                if not isinstance(base_index, int):
                    continue
                for offset in range(100):
                    try:
                        comment = get_extra_cmt(ea, base_index + offset)
                    except Exception:
                        break
                    if not comment:
                        break
                    text = ida_lines.tag_remove(comment).strip()
                    if text and text not in seen:
                        seen.add(text)
                        yield text

        def _iter_chunk_code_heads(chunk_ranges):
            for start_ea, end_ea in chunk_ranges:
                ea = int(start_ea)
                while ea != idc.BADADDR and ea < end_ea:
                    try:
                        flags = ida_bytes.get_flags(ea)
                    except Exception:
                        break
                    if ida_bytes.is_code(flags):
                        yield ea
                    try:
                        next_ea = idc.next_head(ea, end_ea)
                    except Exception:
                        break
                    if next_ea == idc.BADADDR or next_ea <= ea:
                        break
                    ea = next_ea

        def _render_disasm_lines(eas):
            lines = []
            for ea in eas:
                ea = int(ea)
                address_text = _format_address(ea)
                for comment in _iter_comment_lines(ea):
                    lines.append(f"{{address_text}}                 ; {{comment}}")
                disasm_line = ida_lines.tag_remove(
                    idc.generate_disasm_line(ea, 0) or ''
                ).strip()
                if disasm_line:
                    lines.append(f"{{address_text}}                 {{disasm_line}}")
            return '\n'.join(lines).strip()

        def get_disasm(start_ea):
            func = ida_funcs.get_func(start_ea)
            if func is None:
                return ''
            chunk_ranges = _collect_chunk_ranges(func)
            fallback_eas = sorted(
                set(int(ea) for ea in _iter_chunk_code_heads(chunk_ranges))
            )
            if not fallback_eas:
                return ''
            try:
                pending_eas = [int(func.start_ea)]
                visited_eas = set()
                collected_eas = set()
                max_steps = len(fallback_eas) * 4 + 256
                steps = 0
                while pending_eas and steps < max_steps:
                    ea = int(pending_eas.pop())
                    while True:
                        if not _is_in_chunk_ranges(ea, chunk_ranges):
                            break
                        flags = ida_bytes.get_flags(ea)
                        if not ida_bytes.is_code(flags) or ea in visited_eas:
                            break
                        visited_eas.add(ea)
                        collected_eas.add(ea)
                        steps += 1
                        mnem = (idc.print_insn_mnem(ea) or '').lower()
                        refs = [
                            int(ref)
                            for ref in idautils.CodeRefsFrom(ea, False)
                            if _is_in_chunk_ranges(int(ref), chunk_ranges)
                        ]
                        chunk_end = _find_chunk_end(ea, chunk_ranges)
                        next_ea = (
                            idc.next_head(ea, chunk_end)
                            if chunk_end is not None
                            else idc.BADADDR
                        )
                        if mnem in (
                            'ret', 'retn', 'retf', 'iret', 'iretd', 'iretq',
                            'int3', 'hlt', 'ud2',
                        ):
                            break
                        if mnem == 'jmp':
                            for ref in reversed(refs):
                                if ref not in visited_eas:
                                    pending_eas.append(ref)
                            break
                        if mnem.startswith('j'):
                            for ref in reversed(refs):
                                if ref not in visited_eas:
                                    pending_eas.append(ref)
                            if next_ea == idc.BADADDR or next_ea <= ea:
                                break
                            ea = int(next_ea)
                            continue
                        if next_ea == idc.BADADDR or next_ea <= ea:
                            break
                        ea = int(next_ea)
                collected_eas.update(fallback_eas)
                return _render_disasm_lines(sorted(collected_eas))
            except Exception:
                return _render_disasm_lines(fallback_eas)

        def get_pseudocode(start_ea):
            if ida_hexrays is None:
                return ''
            try:
                if not ida_hexrays.init_hexrays_plugin():
                    return ''
                cfunc = ida_hexrays.decompile(start_ea)
            except Exception:
                return ''
            if not cfunc:
                return ''
            return '\n'.join(
                ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
            )

        globals().update(locals())
        func = ida_funcs.get_func(func_ea)
        if func is None:
            raise ValueError(f"Function not found: {{hex(func_ea)}}")
        func_start = int(func.start_ea)
        result = json.dumps(
            {{
                "func_name": ida_funcs.get_func_name(func_start) or f"sub_{{func_start:X}}",
                "func_va": hex(func_start),
                "disasm_code": get_disasm(func_start),
                "procedure": get_pseudocode(func_start),
            }}
        )
        """
        ).strip()
        + "\n"
    )


_FUNC_XREF_PY_EVAL_TEMPLATE = r"""
import ida_auto, ida_bytes, ida_funcs, ida_name, ida_nalt, ida_netnode, ida_segment, ida_ua, ida_xref, idaapi, idautils, idc, json, math, struct

spec = json.loads(SPEC_PLACEHOLDER)
image_base = IMAGE_BASE_PLACEHOLDER
ida_auto.auto_wait()
pointer_size = 8 if idaapi.inf_is_64bit() else 4
UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT = 0x200
UNDEFINED_FUNC_RECOVERY_MAX_SOURCE_DEPTH = 4
PAD_BYTES = {0xCC, 0x90}
SIGNATURE_XREF_PROBE_MAX_CANDIDATES = 256

def _probe_function_start(code_addr):
    func = ida_funcs.get_func(int(code_addr))
    if func is not None:
        return {'status': 'resolved', 'func_start': int(func.start_ea)}
    candidates = set()
    unresolved_sources = set()
    lower_bound = max(0, int(code_addr) - UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT)
    for probe_ea in range(int(code_addr), lower_bound - 1, -1):
        other_func = ida_funcs.get_func(probe_ea)
        if other_func is not None:
            if candidates:
                break
            return {'status': 'blocked_existing_function'}
        if not ida_bytes.is_code(ida_bytes.get_full_flags(probe_ea)):
            continue
        for xref in idautils.XrefsTo(probe_ea, 0):
            mnem = (idc.print_insn_mnem(xref.frm) or '').lower()
            if mnem not in ('call', 'jmp', 'lea'):
                continue
            if probe_ea not in [idc.get_operand_value(xref.frm, index) for index in range(3)]:
                continue
            ref_func = ida_funcs.get_func(xref.frm)
            if ref_func is None:
                unresolved_sources.add(int(xref.frm))
                continue
            candidates.add(probe_ea)
    result = {'status': 'no_entry'}
    if len(candidates) == 1:
        result = {'status': 'needs_define', 'entry': next(iter(candidates))}
    elif len(candidates) > 1:
        result = {'status': 'multiple_entries'}
    if unresolved_sources:
        result['unresolved_sources'] = sorted(unresolved_sources)
    return result

def _function_start(ea, recovery_seen=None, recovery_depth=0):
    code_addr = int(ea)
    recovery_seen = set() if recovery_seen is None else recovery_seen
    if code_addr in recovery_seen:
        return None
    recovery_seen.add(code_addr)
    probe = _probe_function_start(code_addr)
    while probe:
        status = probe.get('status')
        if status == 'resolved':
            return int(probe['func_start'])
        if status == 'needs_define':
            try:
                ida_funcs.add_func(int(probe['entry']))
            except Exception:
                return None
            func = ida_funcs.get_func(code_addr)
            return int(func.start_ea) if func is not None else None
        if recovery_depth >= UNDEFINED_FUNC_RECOVERY_MAX_SOURCE_DEPTH:
            return None
        recovered_source = False
        for source in probe.get('unresolved_sources') or []:
            if _function_start(source, recovery_seen, recovery_depth + 1) is not None:
                recovered_source = True
                break
        if not recovered_source:
            return None
        probe = _probe_function_start(code_addr)
    return None

def _functions_referencing(ea):
    found = set()
    for xref in idautils.XrefsTo(int(ea), 0):
        start = _function_start(xref.frm)
        if start is not None:
            found.add(start)
    return found

def _single_call_or_jump_candidates(ea):
    call_jump_types = {
        getattr(ida_xref, name)
        for name in ('fl_CF', 'fl_CN', 'fl_JF', 'fl_JN')
        if hasattr(ida_xref, name)
    }
    code_addrs = set()
    for xref in idautils.XrefsTo(int(ea), 0):
        mnem = (idc.print_insn_mnem(xref.frm) or '').lower()
        if xref.type not in call_jump_types and mnem not in {'call', 'jmp'}:
            continue
        code_addrs.add(int(xref.frm))
    counts = {}
    for code_addr in sorted(code_addrs):
        start = _function_start(code_addr)
        if start is not None:
            counts[start] = counts.get(start, 0) + 1
    return {start for start, count in counts.items() if count == 1}

def _address_candidates(values):
    found = set()
    for value in values or []:
        if value is None:
            continue
        start = _function_start(int(value))
        if start is not None:
            found.add(start)
    return found

def _string_items():
    strings = idautils.Strings(default_setup=False)
    min_length = spec.get('string_min_length')
    if min_length is None:
        return strings
    expected_state = {
        'version': STRING_SETUP_STATE_VERSION_PLACEHOLDER,
        'minlen': int(min_length),
        'strtypes': 'STRTYPE_C',
    }
    try:
        node = ida_netnode.netnode(STRING_SETUP_STATE_NODE_PLACEHOLDER, 0, True)
        raw_state = node.valobj()
        if isinstance(raw_state, bytes):
            raw_state = raw_state.decode('utf-8', errors='ignore')
        current_state = json.loads(str(raw_state)) if raw_state not in (None, '') else None
    except Exception:
        node = None
        current_state = None
    if current_state != expected_state:
        strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=int(min_length))
        if node is not None:
            try:
                node.set(json.dumps(expected_state, sort_keys=True))
            except Exception:
                pass
    return strings

def _string_candidates(query):
    exact = str(query).startswith('FULLMATCH:')
    needle = str(query)[10:] if exact else str(query)
    found = set()
    for item in _string_items():
        text = str(item)
        if (text == needle) if exact else (needle in text):
            found.update(_functions_referencing(int(item.ea)))
    return found

def _named_ea(value):
    text = str(value)
    try:
        return int(text, 0)
    except Exception:
        ea = ida_name.get_name_ea(idaapi.BADADDR, text)
        return None if ea == idaapi.BADADDR else int(ea)

def _named_candidates(value):
    ea = _named_ea(value)
    return set() if ea is None else _functions_referencing(ea)

def _is_same_exec_segment(ea, segment_start):
    segment = ida_segment.getseg(int(ea))
    return bool(
        segment
        and int(segment.start_ea) == int(segment_start)
        and int(getattr(segment, 'perm', 0)) & int(getattr(idaapi, 'SEGPERM_EXEC', 4))
    )

def _try_decode_padding_nop(cursor, limit_end):
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, int(cursor))
    if not size or int(cursor) + int(size) > int(limit_end):
        return None
    if (idc.print_insn_mnem(int(cursor)) or '').lower() != 'nop':
        return None
    raw = ida_bytes.get_bytes(int(cursor), int(size))
    if not raw or len(raw) != int(size):
        return None
    return list(raw)

def _consume_padding(cursor, limit_end, segment_start):
    padding = []
    while cursor < limit_end:
        if not _is_same_exec_segment(cursor, segment_start):
            return cursor, padding, False
        flags = ida_bytes.get_full_flags(cursor)
        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            return cursor, padding, True
        nop_bytes = _try_decode_padding_nop(cursor, limit_end)
        if nop_bytes:
            padding.append(nop_bytes)
            cursor += len(nop_bytes)
            continue
        byte = ida_bytes.get_byte(cursor)
        if byte == idaapi.BADADDR or byte not in PAD_BYTES:
            return cursor, padding, False
        padding.append([int(byte)])
        cursor += 1
    return cursor, padding, False

def _signature(start):
    func = ida_funcs.get_func(start)
    if func is None:
        return ''
    tokens = []
    ea = int(func.start_ea)
    func_end = int(func.end_ea)
    fixed = 0
    allow_across = bool(spec.get('allow_across_function_boundary'))
    max_fixed = 256 if allow_across else 24
    max_tokens = 256 if allow_across else 64
    segment = ida_segment.getseg(ea)
    segment_start = int(segment.start_ea) if segment is not None else idaapi.BADADDR
    limit_end = ea + max_tokens if allow_across else func_end
    while ea < limit_end and len(tokens) < max_tokens and fixed < max_fixed:
        flags = ida_bytes.get_full_flags(ea)
        if allow_across and (ea >= func_end or not ida_bytes.is_code(flags) or not ida_bytes.is_head(flags)):
            ea, padding, can_continue = _consume_padding(ea, limit_end, segment_start)
            for padding_bytes in padding:
                tokens.extend('%02X' % byte for byte in padding_bytes)
                fixed += len(padding_bytes)
            if len(tokens) >= max_tokens or fixed >= max_fixed or not can_continue:
                break
            flags = ida_bytes.get_full_flags(ea)
        if not _is_same_exec_segment(ea, segment_start):
            break
        if not ida_bytes.is_code(flags) or not ida_bytes.is_head(flags):
            break
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if not size:
            break
        raw = list(ida_bytes.get_bytes(ea, size) or b'')
        wildcard_from = size
        if raw and raw[0] in (0xE8, 0xE9) and size >= 5:
            wildcard_from = 1
        else:
            for op in insn.ops:
                if op.type == ida_ua.o_void:
                    break
                if op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem, ida_ua.o_displ):
                    wildcard_from = min(wildcard_from, int(op.offb or size))
                elif op.type == ida_ua.o_imm and ida_segment.getseg(int(op.value)) is not None:
                    wildcard_from = min(wildcard_from, int(op.offb or size))
        for index, byte in enumerate(raw):
            if index >= wildcard_from:
                tokens.append('??')
            else:
                tokens.append('%02X' % byte)
                fixed += 1
        ea += size
    return ' '.join(tokens)

SINGLE_FLOAT_MNEMS = {
    'addss', 'subss', 'mulss', 'divss', 'minss', 'maxss', 'sqrtss', 'movss', 'comiss', 'ucomiss',
    'vaddss', 'vsubss', 'vmulss', 'vdivss', 'vminss', 'vmaxss', 'vsqrtss', 'vmovss', 'vcomiss', 'vucomiss',
}
DOUBLE_FLOAT_MNEMS = {
    'addsd', 'subsd', 'mulsd', 'divsd', 'minsd', 'maxsd', 'sqrtsd', 'movsd', 'comisd', 'ucomisd',
    'vaddsd', 'vsubsd', 'vmulsd', 'vdivsd', 'vminsd', 'vmaxsd', 'vsqrtsd', 'vmovsd', 'vcomisd', 'vucomisd',
}
MEMORY_OPERAND_TYPES = {idc.o_mem, idc.o_displ, idc.o_phrase}

def _scalar_float_kind(ea):
    mnem = (idc.print_insn_mnem(ea) or '').lower()
    if mnem in SINGLE_FLOAT_MNEMS and mnem.endswith('ss'):
        return 'float'
    if mnem in DOUBLE_FLOAT_MNEMS and mnem.endswith('sd'):
        return 'double'
    return None

def _has_xmm_operand(ea):
    return any('xmm' in (idc.print_operand(ea, index) or '').lower() for index in range(8))

def _is_readonly_float_segment(ea):
    segment = ida_segment.getseg(int(ea))
    if segment is None:
        return False
    name = ida_segment.get_segm_name(segment) or ''
    return name == '.rdata' or name.startswith('.rodata')

def _float_matches(value, expected, kind):
    epsilon = 1e-6 if kind == 'float' else 1e-12
    return abs(value - expected) < epsilon

def _function_contains_signature(start, signature):
    func = ida_funcs.get_func(start)
    if func is None:
        return False
    match_ea = ida_bytes.find_bytes(
        signature,
        int(func.start_ea),
        range_end=int(func.end_ea),
        flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
        radix=16,
    )
    return match_ea != idaapi.BADADDR and match_ea < int(func.end_ea)

def _intersected_candidates(sets):
    if not sets:
        return set()
    result = set(sets[0])
    for values in sets[1:]:
        result.intersection_update(values)
    return result

def _signature_candidates(narrowed, signature, match_eas):
    if narrowed and len(narrowed) <= SIGNATURE_XREF_PROBE_MAX_CANDIDATES:
        return {start for start in narrowed if _function_contains_signature(start, signature)}
    return _address_candidates(match_eas)

def _function_matches_float_filters(start, required_values, excluded_values):
    required_hits = [False] * len(required_values)
    excluded_hit = False
    for ea in idautils.FuncItems(start):
        kind = _scalar_float_kind(ea)
        if kind is None or not _has_xmm_operand(ea):
            continue
        for operand_index in range(8):
            if idc.get_operand_type(ea, operand_index) not in MEMORY_OPERAND_TYPES:
                continue
            target_ea = idc.get_operand_value(ea, operand_index)
            if not _is_readonly_float_segment(target_ea):
                continue
            width, fmt = (4, '<f') if kind == 'float' else (8, '<d')
            raw = ida_bytes.get_bytes(int(target_ea), width)
            if not raw or len(raw) != width:
                continue
            try:
                value = struct.unpack(fmt, raw)[0]
            except Exception:
                continue
            if not math.isfinite(value):
                continue
            for index, expected in enumerate(required_values):
                if _float_matches(value, expected, kind):
                    required_hits[index] = True
            for expected in excluded_values:
                if _float_matches(value, expected, kind):
                    excluded_hit = True
    return all(required_hits) and not excluded_hit

globals().update(locals())
positive_sets = []
vtable_candidates = _address_candidates(spec.get('vtable_entries'))
for value in spec.get('xref_strings') or []:
    positive_sets.append(_string_candidates(value))
for value in spec.get('xref_gvs') or []:
    positive_sets.append(_named_candidates(value))
signature_texts = spec.get('xref_signatures') or []
signature_ea_sets = spec.get('xref_signature_ea_sets') or []
for index, signature in enumerate(signature_texts):
    match_eas = signature_ea_sets[index] if index < len(signature_ea_sets) else []
    positive_sets.append(
        _signature_candidates(_intersected_candidates(positive_sets), signature, match_eas)
    )
if spec.get('inline_alias') is not None:
    alias_ea = int(spec['inline_alias'])
    alias_callers = _single_call_or_jump_candidates(alias_ea)
    positive_sets.append(alias_callers or _address_candidates([alias_ea]))
for value in spec.get('xref_funcs') or []:
    dep_ea = _named_ea(value)
    callers = set() if dep_ea is None else _functions_referencing(dep_ea)
    dep_start = None if dep_ea is None else _function_start(dep_ea)
    if not callers and dep_start is not None and dep_start in vtable_candidates:
        callers = {dep_start}
    positive_sets.append(callers)
if spec.get('vtable_entries'):
    positive_sets.append(vtable_candidates)

if positive_sets:
    candidates = set(positive_sets[0])
    for values in positive_sets[1:]:
        candidates.intersection_update(values)
else:
    candidates = set()

excluded = set()
for value in spec.get('exclude_strings') or []:
    excluded.update(_string_candidates(value))
for value in spec.get('exclude_gvs') or []:
    excluded.update(_named_candidates(value))
for value in spec.get('exclude_funcs') or []:
    excluded.update(_address_candidates([_named_ea(value)]))
for value in spec.get('exclude_callees') or []:
    excluded.update(_named_candidates(value))
excluded.update(_address_candidates(spec.get('exclude_signature_eas')))
candidates.difference_update(excluded)

required_floats = [float(value) for value in spec.get('xref_floats') or []]
excluded_floats = [float(value) for value in spec.get('exclude_floats') or []]
if required_floats or excluded_floats:
    candidates = {
        start
        for start in candidates
        if _function_matches_float_filters(start, required_floats, excluded_floats)
    }

items = []
for start in sorted(candidates):
    func = ida_funcs.get_func(start)
    if func is None:
        continue
    items.append({
        'func_name': spec['func_name'],
        'func_va': hex(start),
        'func_rva': hex(start - image_base),
        'func_size': hex(int(func.end_ea) - start),
        'func_sig': _signature(start),
    })

if len(items) == 1:
    try:
        ida_name.set_name(int(items[0]['func_va'], 0), spec['func_name'], ida_name.SN_FORCE)
    except Exception:
        pass

result = json.dumps({'pointer_size': pointer_size, 'candidates': items})
"""


def _build_func_xref_py_eval(spec, image_base):
    serialized_spec = json.dumps(spec, separators=(",", ":"))
    return (
        _FUNC_XREF_PY_EVAL_TEMPLATE.replace("SPEC_PLACEHOLDER", repr(serialized_spec))
        .replace("IMAGE_BASE_PLACEHOLDER", str(int(image_base)))
        .replace("STRING_SETUP_STATE_NODE_PLACEHOLDER", repr(IDA_STRING_SETUP_STATE_NODE))
        .replace("STRING_SETUP_STATE_VERSION_PLACEHOLDER", str(IDA_STRING_SETUP_STATE_VERSION))
    )


def _func_xref_spec_with_across(spec, allow_across_function_boundary):
    if not allow_across_function_boundary:
        return spec
    spec = dict(spec)
    spec["allow_across_function_boundary"] = True
    return spec


def _normalize_func_xref_specs(specs):
    normalized = {}
    for raw_spec in specs or ():
        if not isinstance(raw_spec, Mapping) or set(raw_spec) - FUNC_XREF_ALLOWED_KEYS:
            return None
        func_name = raw_spec.get("func_name")
        if not isinstance(func_name, str) or not func_name or func_name in normalized:
            return None
        spec = {"func_name": func_name}
        for key in FUNC_XREF_LIST_KEYS:
            values = raw_spec.get(key, [])
            if not isinstance(values, (tuple, list)) or any(
                not isinstance(value, str) or not value for value in values
            ):
                return None
            if key in {"xref_floats", "exclude_floats"}:
                parsed_values = []
                for value in values:
                    try:
                        parsed = float(value)
                    except ValueError:
                        return None
                    if not math.isfinite(parsed):
                        return None
                    parsed_values.append(value.strip())
                values = parsed_values
            spec[key] = list(values)
        inline_alias = raw_spec.get("inline_alias")
        if inline_alias is not None and (not isinstance(inline_alias, str) or not inline_alias):
            return None
        spec["inline_alias"] = inline_alias
        if (
            not any(spec[key] for key in ("xref_strings", "xref_gvs", "xref_signatures", "xref_funcs"))
            and not inline_alias
        ):
            return None
        normalized[func_name] = spec
    return normalized


async def _find_byte_matches(session, signature, *, limit=1000):
    try:
        normalized_signature = normalize_signature(signature)
        raw = await session.call_tool("find_bytes", {"patterns": [normalized_signature], "limit": limit})
    except Exception:  # noqa: BLE001 - MCP failures and signature normalization must fail closed.
        return None
    payload = parse_mcp_result(raw)
    if isinstance(payload, Mapping) and "matches" in payload:
        entries = [payload]
    elif isinstance(payload, list):
        entries = payload
    else:
        return None
    if len(entries) != 1 or not isinstance(entries[0], Mapping):
        return None
    matches = entries[0].get("matches")
    if not isinstance(matches, list):
        return None
    try:
        return [int(value, 0) if isinstance(value, str) else int(value) for value in matches]
    except (TypeError, ValueError):
        return None


def _is_explicit_address_literal(value):
    return isinstance(value, str) and len(value.strip()) > 2 and value.strip().lower().startswith("0x")


def _dependency_address(new_binary_dir, stem, platform, field, *, allow_explicit=False):
    text = str(stem).strip()
    if _is_explicit_address_literal(text):
        if not allow_explicit:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    try:
        path = _resolve_artifact_stem_path(new_binary_dir, text, platform)
    except (TypeError, ValueError, OSError):
        return None
    payload = _load_yaml_mapping(path)
    if not payload or payload.get(field) is None:
        return None
    try:
        return _parse_int(payload[field], field)
    except SymbolArtifactError:
        return None


async def preprocess_func_xrefs_via_mcp(
    session,
    func_name,
    xref_strings,
    xref_gvs,
    xref_signatures,
    xref_funcs,
    exclude_funcs,
    exclude_strings,
    exclude_gvs,
    exclude_signatures,
    new_binary_dir,
    platform,
    image_base,
    vtable_class=None,
    allow_func_sig_across_function_boundary=False,
    debug=False,
    xref_floats=None,
    exclude_floats=None,
    inline_alias=None,
    exclude_callees=None,
):
    del debug
    try:
        required_float_values = [float(value) for value in xref_floats or ()]
        excluded_float_values = [float(value) for value in exclude_floats or ()]
    except (TypeError, ValueError):
        return None
    if any(not math.isfinite(value) for value in required_float_values + excluded_float_values):
        return None
    symbolic_func_dependencies = list(xref_funcs or ()) + list(exclude_funcs or ()) + list(exclude_callees or ())
    if inline_alias:
        symbolic_func_dependencies.append(inline_alias)
    symbolic_gv_dependencies = [
        value for value in list(xref_gvs or ()) + list(exclude_gvs or ()) if not _is_explicit_address_literal(value)
    ]
    if (symbolic_func_dependencies or symbolic_gv_dependencies or vtable_class) and not new_binary_dir:
        return None
    spec = {
        "func_name": func_name,
        "xref_strings": list(xref_strings or ()),
        "xref_gvs": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": list(exclude_strings or ()),
        "exclude_gvs": [],
        "xref_floats": required_float_values,
        "exclude_floats": excluded_float_values,
        "exclude_callees": [],
        "string_min_length": _resolve_ida_string_min_length_config(),
    }
    for source, field, destination, allow_explicit in (
        (xref_gvs, "gv_va", "xref_gvs", True),
        (xref_funcs, "func_va", "xref_funcs", False),
        (exclude_funcs, "func_va", "exclude_funcs", False),
        (exclude_gvs, "gv_va", "exclude_gvs", True),
        (exclude_callees, "func_va", "exclude_callees", False),
    ):
        for value in source or ():
            address = _dependency_address(
                new_binary_dir,
                value,
                platform,
                field,
                allow_explicit=allow_explicit,
            )
            if address is None:
                return None
            spec[destination].append(address)
    spec["inline_alias"] = None
    if inline_alias:
        spec["inline_alias"] = _dependency_address(
            new_binary_dir,
            inline_alias,
            platform,
            "func_va",
            allow_explicit=False,
        )
        if spec["inline_alias"] is None:
            return None
    spec["xref_signatures"] = []
    spec["xref_signature_ea_sets"] = []
    for signature in xref_signatures or ():
        try:
            normalized_signature = normalize_signature(signature)
        except SymbolArtifactError:
            return None
        matches = await _find_byte_matches(session, normalized_signature)
        if matches is None:
            return None
        spec["xref_signatures"].append(normalized_signature)
        spec["xref_signature_ea_sets"].append(matches)
    spec["exclude_signature_eas"] = []
    for signature in exclude_signatures or ():
        matches = await _find_byte_matches(session, signature)
        if matches is None:
            return None
        spec["exclude_signature_eas"].extend(matches)
    spec["vtable_entries"] = []
    if vtable_class:
        try:
            vtable_path = _vtable_yaml_path(new_binary_dir, vtable_class, platform)
        except (TypeError, ValueError, OSError):
            return None
        vtable = _load_yaml_mapping(vtable_path)
        if not vtable:
            return None
        for value in (vtable.get("vtable_entries") or {}).values():
            try:
                spec["vtable_entries"].append(_parse_int(value, "vtable entry"))
            except SymbolArtifactError:
                return None
        if not spec["vtable_entries"]:
            return None
    positive = (
        spec["xref_strings"]
        or spec["xref_gvs"]
        or spec["xref_signatures"]
        or spec["xref_funcs"]
        or spec["inline_alias"]
    )
    if not positive:
        return None
    try:
        raw = await session.call_tool(
            "py_eval",
            {
                "code": _build_func_xref_py_eval(
                    _func_xref_spec_with_across(spec, allow_func_sig_across_function_boundary),
                    image_base,
                )
            },
        )
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    payload = parse_mcp_result(raw)
    if not isinstance(payload, Mapping) or payload.get("pointer_size") != 4:
        return None
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1 or not isinstance(candidates[0], Mapping):
        return None
    result = dict(candidates[0])
    result["_pointer_size"] = 4
    try:
        func_va = _parse_int(result.get("func_va"), "func_va")
    except SymbolArtifactError:
        return None
    signature = result.get("func_sig")
    if isinstance(signature, str) and signature.strip():
        unique_ea = await _find_unique_bytes(session, signature)
        if unique_ea != func_va:
            result.pop("func_sig", None)
    else:
        result.pop("func_sig", None)
    if allow_func_sig_across_function_boundary:
        result["func_sig_allow_across_function_boundary"] = True
    return result


def _can_probe_future_func_fast_path(*, func_name, func_xrefs_map, new_binary_dir, platform):
    xref_spec = (func_xrefs_map or {}).get(func_name)
    if not isinstance(xref_spec, Mapping):
        return True
    inline_alias = xref_spec.get("inline_alias")
    dependency_symbol_names = (
        list(xref_spec.get("xref_funcs") or ())
        + list(xref_spec.get("exclude_funcs") or ())
        + list(xref_spec.get("exclude_callees") or ())
        + ([inline_alias] if inline_alias else [])
        + [value for value in xref_spec.get("xref_gvs") or () if not _is_explicit_address_literal(value)]
        + [value for value in xref_spec.get("exclude_gvs") or () if not _is_explicit_address_literal(value)]
    )
    if not dependency_symbol_names:
        return True
    if new_binary_dir is None:
        return False
    return all(
        (path := _resolve_artifact_stem_path(new_binary_dir, symbol_name, platform)) is not None and path.is_file()
        for symbol_name in dependency_symbol_names
    )


def _desired_fields_map(specs):
    if not isinstance(specs, list) or not specs:
        return None
    result = {}
    for item in specs:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            return None
        name, fields = item
        if not isinstance(name, str) or not name or not isinstance(fields, list) or not fields:
            return None
        if name in result or any(not isinstance(field, str) or not field for field in fields):
            return None
        desired_fields = []
        optional_fields = set()
        generation_options = {}
        for raw_field in fields:
            field = raw_field
            if field.endswith("?") and len(field) > 1:
                field = field[:-1]
                optional_fields.add(field)
            if ":" in field:
                directive, raw_value = field.split(":", 1)
                raw_value = raw_value.strip().lower()
                if directive in {
                    "func_sig_allow_across_function_boundary",
                    "func_sig_resolve_jmp_thunk",
                    "gv_sig_allow_across_function_boundary",
                    "vfunc_sig_allow_across_function_boundary",
                    "offset_sig_allow_across_function_boundary",
                }:
                    if raw_value != "true" or directive in generation_options:
                        return None
                    generation_options[directive] = True
                    desired_fields.append(directive)
                    continue
                if directive in {"vfunc_sig_max_match", "offset_sig_max_match"}:
                    try:
                        value = int(raw_value)
                    except ValueError:
                        return None
                    if value <= 0 or directive in generation_options:
                        return None
                    generation_options[directive] = value
                    desired_fields.append(directive)
                    continue
                return None
            if field in {
                "func_sig_allow_across_function_boundary",
                "func_sig_resolve_jmp_thunk",
                "gv_sig_allow_across_function_boundary",
                "vfunc_sig_allow_across_function_boundary",
                "offset_sig_allow_across_function_boundary",
                "vfunc_sig_max_match",
                "offset_sig_max_match",
            }:
                return None
            desired_fields.append(field)
        result[name] = {
            "fields": desired_fields,
            "optional_fields": optional_fields,
            "generation_options": generation_options,
        }
    return result


def _output_for_symbol(expected_outputs, symbol_name):
    matches = []
    for value in expected_outputs or ():
        path = Path(value)
        stem = path.name
        for suffix in (".windows.yaml", ".linux.yaml", ".yaml"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        if stem == symbol_name:
            matches.append(path)
    return matches[0] if len(matches) == 1 else None


def _load_yaml_mapping(path):
    if not path or not Path(path).is_file():
        return None
    try:
        value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return value if isinstance(value, dict) else None


def _old_path_for_output(old_yaml_map, output):
    if not old_yaml_map or output is None:
        return None
    output_key = os.path.normcase(os.path.abspath(os.fspath(output)))
    for new_path, old_path in old_yaml_map.items():
        if os.path.normcase(os.path.abspath(os.fspath(new_path))) == output_key:
            return old_path
    return None


async def _find_unique_bytes(session, signature):
    try:
        raw = await session.call_tool("find_bytes", {"patterns": [signature], "limit": 2})
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    payload = parse_mcp_result(raw)
    if isinstance(payload, Mapping) and "matches" in payload:
        entries = [payload]
    elif isinstance(payload, list):
        entries = payload
    else:
        return None
    if not entries or not isinstance(entries[0], Mapping):
        return None
    matches = entries[0].get("matches")
    count = entries[0].get("n", len(matches) if isinstance(matches, list) else 0)
    try:
        count = int(count)
    except (TypeError, ValueError):
        return None
    if not isinstance(matches, list) or count != 1 or len(matches) != 1:
        return None
    try:
        return int(matches[0], 0) if isinstance(matches[0], str) else int(matches[0])
    except (TypeError, ValueError):
        return None


_INSPECT_FUNCTION_PY_EVAL = r"""
import ida_bytes, ida_funcs, ida_name, ida_segment, ida_ua, idaapi, idc, json
ea = EA_PLACEHOLDER
image_base = IMAGE_BASE_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
allow_across_function_boundary = ALLOW_ACROSS_FUNCTION_BOUNDARY_PLACEHOLDER
PAD_BYTES = {0xCC, 0x90}
func = ida_funcs.get_func(ea)
if func is None:
    try:
        ida_funcs.add_func(ea)
    except Exception:
        pass
    func = ida_funcs.get_func(ea)

def _is_same_exec_segment(cursor, segment_start):
    segment = ida_segment.getseg(int(cursor))
    return bool(
        segment
        and int(segment.start_ea) == int(segment_start)
        and int(getattr(segment, 'perm', 0)) & int(getattr(idaapi, 'SEGPERM_EXEC', 4))
    )

def _try_decode_padding_nop(cursor, limit_end):
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, int(cursor))
    if not size or int(cursor) + int(size) > int(limit_end):
        return None
    if (idc.print_insn_mnem(int(cursor)) or '').lower() != 'nop':
        return None
    raw = ida_bytes.get_bytes(int(cursor), int(size))
    if not raw or len(raw) != int(size):
        return None
    return list(raw)

def _consume_padding(cursor, limit_end, segment_start):
    padding = []
    while cursor < limit_end:
        if not _is_same_exec_segment(cursor, segment_start):
            return cursor, padding, False
        flags = ida_bytes.get_full_flags(cursor)
        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            return cursor, padding, True
        nop_bytes = _try_decode_padding_nop(cursor, limit_end)
        if nop_bytes:
            padding.append(nop_bytes)
            cursor += len(nop_bytes)
            continue
        byte = ida_bytes.get_byte(cursor)
        if byte == idaapi.BADADDR or byte not in PAD_BYTES:
            return cursor, padding, False
        padding.append([int(byte)])
        cursor += 1
    return cursor, padding, False

def _signature(start, end):
    tokens = []
    current = start
    fixed = 0
    max_fixed = 256 if allow_across_function_boundary else 24
    max_tokens = 256 if allow_across_function_boundary else 64
    segment = ida_segment.getseg(start)
    segment_start = int(segment.start_ea) if segment is not None else idaapi.BADADDR
    limit_end = start + max_tokens if allow_across_function_boundary else end
    while current < limit_end and len(tokens) < max_tokens and fixed < max_fixed:
        flags = ida_bytes.get_full_flags(current)
        if allow_across_function_boundary and (
            current >= end or not ida_bytes.is_code(flags) or not ida_bytes.is_head(flags)
        ):
            current, padding, can_continue = _consume_padding(current, limit_end, segment_start)
            for padding_bytes in padding:
                tokens.extend('%02X' % byte for byte in padding_bytes)
                fixed += len(padding_bytes)
            if len(tokens) >= max_tokens or fixed >= max_fixed or not can_continue:
                break
            flags = ida_bytes.get_full_flags(current)
        if not _is_same_exec_segment(current, segment_start):
            break
        if not ida_bytes.is_code(flags) or not ida_bytes.is_head(flags):
            break
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, current)
        if not size:
            break
        raw = list(ida_bytes.get_bytes(current, size) or b'')
        wildcard_from = size
        if raw and raw[0] in (0xE8, 0xE9) and size >= 5:
            wildcard_from = 1
        else:
            for op in insn.ops:
                if op.type == ida_ua.o_void:
                    break
                if op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem, ida_ua.o_displ):
                    wildcard_from = min(wildcard_from, int(op.offb or size))
                elif op.type == ida_ua.o_imm and ida_segment.getseg(int(op.value)) is not None:
                    wildcard_from = min(wildcard_from, int(op.offb or size))
        for index, byte in enumerate(raw):
            if index >= wildcard_from:
                tokens.append('??')
            else:
                tokens.append('%02X' % byte)
                fixed += 1
        current += size
    return ' '.join(tokens)

globals().update(locals())
if func is None or int(func.start_ea) != ea:
    result = json.dumps({'pointer_size': pointer_size, 'function': None})
else:
    end = int(func.end_ea)
    result = json.dumps({'pointer_size': pointer_size, 'function': {
        'func_va': hex(ea),
        'func_rva': hex(ea - image_base),
        'func_size': hex(end - ea),
        'func_sig': _signature(ea, end),
    }})
"""


async def _inspect_function_via_mcp(session, ea, image_base, func_name, allow_across_function_boundary=False):
    code = (
        _INSPECT_FUNCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(int(ea)))
        .replace("IMAGE_BASE_PLACEHOLDER", str(int(image_base)))
        .replace("ALLOW_ACROSS_FUNCTION_BOUNDARY_PLACEHOLDER", "True" if allow_across_function_boundary else "False")
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    if not isinstance(payload, Mapping) or payload.get("pointer_size") != 4:
        return None
    data = payload.get("function")
    if not isinstance(data, Mapping):
        return None
    result = {"func_name": func_name, **dict(data), "_pointer_size": 4}
    signature = result.get("func_sig")
    if not isinstance(signature, str) or not signature.strip():
        return None
    try:
        func_va = _parse_int(result.get("func_va"), "func_va")
    except SymbolArtifactError:
        return None
    if await _find_unique_bytes(session, signature) != func_va:
        return None
    return result


async def preprocess_func_sig_via_mcp(
    session,
    new_path,
    old_path,
    image_base,
    new_binary_dir,
    platform,
    func_name=None,
    debug=False,
    mangled_class_names=None,
    direct_func_va=None,
    direct_vtable_class=None,
    direct_vfunc_offset=None,
    allow_func_sig_across_function_boundary=False,
):
    del new_binary_dir, platform, debug, mangled_class_names, direct_vtable_class, direct_vfunc_offset
    old_data = _load_yaml_mapping(old_path)
    resolved_name = func_name or (old_data or {}).get("func_name") or Path(new_path).name.rsplit(".", 2)[0]
    if direct_func_va is not None:
        ea = _parse_int(direct_func_va, "direct_func_va")
    else:
        signature = (old_data or {}).get("func_sig")
        if not signature:
            return None
        ea = await _find_unique_bytes(session, signature)
        if ea is None:
            return None
    allow_across = allow_func_sig_across_function_boundary or bool(
        (old_data or {}).get("func_sig_allow_across_function_boundary")
    )
    result = await _inspect_function_via_mcp(
        session, ea, image_base, resolved_name, allow_across_function_boundary=allow_across
    )
    if result is None:
        return None
    if old_data and old_data.get("func_sig"):
        result["func_sig"] = normalize_signature(old_data["func_sig"])
    if allow_func_sig_across_function_boundary or (old_data or {}).get("func_sig_allow_across_function_boundary"):
        result["func_sig_allow_across_function_boundary"] = True
    return result


async def preprocess_patch_via_mcp(session, new_path, old_path, image_base, new_binary_dir, platform, debug=False):
    del new_binary_dir, platform, debug
    old_data = _load_yaml_mapping(old_path)
    if not old_data or not old_data.get("patch_sig") or not old_data.get("patch_bytes"):
        return None
    ea = await _find_unique_bytes(session, old_data["patch_sig"])
    if ea is None or ea < int(image_base):
        return None
    result = {
        "patch_name": old_data.get("patch_name") or Path(new_path).name.rsplit(".", 2)[0],
        "patch_va": hex(ea),
        "patch_rva": hex(ea - int(image_base)),
        "patch_sig": normalize_signature(old_data["patch_sig"]),
        "patch_bytes": old_data["patch_bytes"],
    }
    if old_data.get("patch_sig_disp") is not None:
        result["patch_sig_disp"] = _parse_int(old_data["patch_sig_disp"], "patch_sig_disp")
    return result


_RESOLVE_X86_GV_PY_EVAL = r"""
import ida_bytes, ida_ua, idautils, idaapi, json
sig_addr = SIG_ADDR_PLACEHOLDER
inst_addr = sig_addr + INST_OFFSET_PLACEHOLDER
operand_index = OPERAND_INDEX_PLACEHOLDER
ref_kind = REF_KIND_PLACEHOLDER
deref_count = DEREF_COUNT_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
insn = ida_ua.insn_t()
size = ida_ua.decode_insn(insn, inst_addr)
address = None
if size and pointer_size == 4:
    if ref_kind == 'data_xref':
        refs = sorted(set(int(value) for value in idautils.DataRefsFrom(inst_addr)))
        if 0 <= operand_index < len(refs):
            address = refs[operand_index]
    else:
        operands = []
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
                operands.append(int(op.addr))
            elif op.type == ida_ua.o_imm:
                operands.append(int(op.value))
        if 0 <= operand_index < len(operands):
            address = operands[operand_index]
    for _ in range(deref_count):
        if address is None:
            break
        address = int(ida_bytes.get_dword(address))
result = json.dumps({'pointer_size': pointer_size, 'address': None if address is None else hex(address), 'inst_length': int(size or 0)})
"""


async def preprocess_gv_sig_via_mcp(session, new_path, old_path, image_base, new_binary_dir, platform, debug=False):
    del new_binary_dir, platform, debug
    old_data = _load_yaml_mapping(old_path)
    if not old_data or not old_data.get("gv_sig"):
        return None
    sig_addr = await _find_unique_bytes(session, old_data["gv_sig"])
    if sig_addr is None:
        return None
    inst_offset = _parse_int(old_data.get("gv_inst_offset", 0), "gv_inst_offset")
    ref_kind = old_data.get("gv_ref_kind", "operand")
    ref_index = _parse_int(old_data.get("gv_ref_index", 0), "gv_ref_index")
    deref_count = _parse_int(old_data.get("gv_ref_deref_count", 0), "gv_ref_deref_count")
    code = (
        _RESOLVE_X86_GV_PY_EVAL.replace("SIG_ADDR_PLACEHOLDER", str(sig_addr))
        .replace("INST_OFFSET_PLACEHOLDER", str(inst_offset))
        .replace("OPERAND_INDEX_PLACEHOLDER", str(ref_index))
        .replace("REF_KIND_PLACEHOLDER", json.dumps(ref_kind))
        .replace("DEREF_COUNT_PLACEHOLDER", str(deref_count))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    if not isinstance(payload, Mapping) or payload.get("pointer_size") != 4 or payload.get("address") is None:
        return None
    gv_va = int(payload["address"], 0)
    if gv_va < int(image_base):
        return None
    return {
        "gv_name": old_data.get("gv_name") or Path(new_path).name.rsplit(".", 2)[0],
        "gv_va": hex(gv_va),
        "gv_rva": hex(gv_va - int(image_base)),
        "gv_sig": normalize_signature(old_data["gv_sig"]),
        "gv_sig_va": hex(sig_addr),
        "gv_inst_offset": inst_offset,
        "gv_inst_length": int(payload.get("inst_length", 0)),
        "gv_inst_disp": _parse_int(old_data.get("gv_inst_disp", 0), "gv_inst_disp"),
        "gv_ref_kind": ref_kind,
        "gv_ref_index": ref_index,
        "gv_ref_deref_count": deref_count,
    }


_RESOLVE_STRUCT_OFFSET_PY_EVAL = r"""
import ida_ua, idaapi, json
ea = EA_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
insn = ida_ua.insn_t()
size = ida_ua.decode_insn(insn, ea)
values = []
if size and pointer_size == 4:
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        if op.type == ida_ua.o_displ:
            values.append(int(op.addr) & 0xFFFFFFFF)
result = json.dumps({'pointer_size': pointer_size, 'offsets': values})
"""


async def preprocess_struct_offset_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    del image_base, new_binary_dir, platform, debug
    old_data = _load_yaml_mapping(old_path)
    if not old_data or not old_data.get("offset_sig"):
        return None
    sig_addr = await _find_unique_bytes(session, old_data["offset_sig"])
    if sig_addr is None:
        return None
    sig_disp = _parse_int(old_data.get("offset_sig_disp", 0), "offset_sig_disp")
    code = _RESOLVE_STRUCT_OFFSET_PY_EVAL.replace("EA_PLACEHOLDER", str(sig_addr + sig_disp))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    offsets = payload.get("offsets") if isinstance(payload, Mapping) and payload.get("pointer_size") == 4 else None
    if not isinstance(offsets, list) or len(set(offsets)) != 1:
        return None
    result = {
        "struct_name": old_data.get("struct_name"),
        "member_name": old_data.get("member_name"),
        "offset": hex(int(offsets[0])),
        "offset_sig": normalize_signature(old_data["offset_sig"]),
        "offset_sig_disp": sig_disp,
    }
    if not result["struct_name"] or not result["member_name"]:
        return None
    for field in ("size", "offset_sig_max_match", "offset_sig_allow_across_function_boundary"):
        if field in old_data:
            result[field] = old_data[field]
    return result


_VTABLE_PY_EVAL = r"""
import ida_auto, ida_bytes, ida_funcs, ida_name, ida_segment, idaapi, idautils, json
class_name = CLASS_NAME_PLACEHOLDER
aliases = ALIASES_PLACEHOLDER
ida_auto.auto_wait()
pointer_size = 8 if idaapi.inf_is_64bit() else 4
vtable = None
symbol = ''
all_names = [(int(ea), str(name)) for ea, name in idautils.Names()]
candidates = list(aliases)
candidates.extend(['??_7' + class_name + '@@6B@'])
for candidate in candidates:
    ea = ida_name.get_name_ea(idaapi.BADADDR, candidate)
    if ea != idaapi.BADADDR:
        vtable, symbol = int(ea), candidate
        break
if vtable is None:
    for ea, name in all_names:
        if class_name in name and (name.startswith('_ZTV') or name.startswith('??_7')):
            vtable, symbol = ea, name
            if name.startswith('_ZTV'):
                vtable += pointer_size * 2
            break
entries = {}
if vtable is not None and pointer_size == 4:
    for index in range(512):
        target = int(ida_bytes.get_dword(vtable + index * pointer_size))
        segment = ida_segment.getseg(target)
        if target in (0, idaapi.BADADDR) or segment is None or not (segment.perm & ida_segment.SEGPERM_EXEC):
            break
        func = ida_funcs.get_func(target)
        entries[index] = hex(target)
result = json.dumps({
    'pointer_size': pointer_size,
    'vtable_class': class_name,
    'vtable_symbol': symbol,
    'vtable_va': None if vtable is None else hex(vtable),
    'vtable_entries': entries,
})
"""


async def preprocess_vtable_via_mcp(session, class_name, image_base, platform, debug=False, symbol_aliases=None):
    del platform, debug
    code = _VTABLE_PY_EVAL.replace("CLASS_NAME_PLACEHOLDER", json.dumps(class_name)).replace(
        "ALIASES_PLACEHOLDER", json.dumps(list(symbol_aliases or ()))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    if not isinstance(payload, Mapping) or payload.get("pointer_size") != 4 or not payload.get("vtable_va"):
        return None
    entries = {int(index): str(value) for index, value in (payload.get("vtable_entries") or {}).items()}
    if not entries:
        return None
    va = int(payload["vtable_va"], 0)
    return {
        "vtable_class": class_name,
        "vtable_symbol": payload.get("vtable_symbol") or class_name,
        "vtable_va": hex(va),
        "vtable_rva": hex(va - int(image_base)),
        "vtable_size": hex(len(entries) * 4),
        "vtable_numvfunc": len(entries),
        "vtable_entries": entries,
        "_pointer_size": 4,
    }


def _vtable_yaml_path(new_binary_dir, class_or_stem, platform):
    stem = str(class_or_stem)
    if not stem.endswith("_vtable") and "_vtable" not in stem:
        stem += "_vtable"
    return _resolve_artifact_stem_path(new_binary_dir, stem, platform)


def _is_vtable_artifact_stem(value):
    return "_vtable" in Path(str(value)).name


def _enrich_vfunc_from_vtable(candidate, vtable_name, new_binary_dir, platform):
    data = _load_yaml_mapping(_vtable_yaml_path(new_binary_dir, vtable_name, platform))
    if not data:
        return None
    target_va = int(candidate["func_va"], 0)
    matches = []
    for raw_index, raw_value in (data.get("vtable_entries") or {}).items():
        try:
            value = int(raw_value, 0) if isinstance(raw_value, str) else int(raw_value)
        except (TypeError, ValueError):
            continue
        if value == target_va:
            matches.append(int(raw_index))
    if len(matches) != 1:
        return None
    index = matches[0]
    result = dict(candidate)
    result.update({"vtable_name": str(vtable_name), "vfunc_offset": hex(index * 4), "vfunc_index": index})
    return result


def _enrich_vfunc_from_vtable_data(candidate, vtable_name, vtable_data):
    if not isinstance(vtable_data, Mapping):
        return None
    target_va = _parse_int(candidate.get("func_va"), "func_va")
    matches = []
    for raw_index, raw_value in (vtable_data.get("vtable_entries") or {}).items():
        try:
            if _parse_int(raw_value, "vtable entry") == target_va:
                matches.append(int(raw_index))
        except (SymbolArtifactError, TypeError, ValueError):
            continue
    if len(matches) != 1:
        return None
    index = matches[0]
    result = dict(candidate)
    result.update({"vtable_name": str(vtable_name), "vfunc_offset": hex(index * 4), "vfunc_index": index})
    return result


def _resolve_artifact_stem_path(new_binary_dir, stem, platform):
    base = Path(new_binary_dir).resolve()
    game_root = base.parent
    candidate = (base / f"{stem}.{platform}.yaml").resolve()
    try:
        candidate.relative_to(game_root)
    except ValueError:
        return None
    return candidate


async def preprocess_index_based_vfunc_via_mcp(
    session,
    target_func_name,
    target_output,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    base_vfunc_name,
    inherit_vtable_class,
    generate_func_sig=True,
    slot_only=False,
    allow_func_sig_across_function_boundary=False,
    debug=False,
):
    del old_yaml_map, allow_func_sig_across_function_boundary, debug
    base_path = _resolve_artifact_stem_path(new_binary_dir, base_vfunc_name, platform)
    base = _load_yaml_mapping(base_path)
    if not base:
        return None
    raw_index = base.get("vfunc_index")
    raw_offset = base.get("vfunc_offset")
    if raw_index is None and raw_offset is None:
        return None
    index = (
        _parse_int(raw_index, "vfunc_index") if raw_index is not None else _parse_int(raw_offset, "vfunc_offset") // 4
    )
    if raw_offset is not None and _parse_int(raw_offset, "vfunc_offset") != index * 4:
        return None
    slot_data = {
        "func_name": target_func_name,
        "vtable_name": str(inherit_vtable_class),
        "vfunc_offset": hex(index * 4),
        "vfunc_index": index,
    }
    if slot_only and not generate_func_sig:
        slot_data["_pointer_size"] = 4
        return slot_data
    vtable = _load_yaml_mapping(_vtable_yaml_path(new_binary_dir, inherit_vtable_class, platform))
    entries = (vtable or {}).get("vtable_entries") or {}
    raw_target = entries.get(index, entries.get(str(index)))
    if raw_target is None:
        return None
    try:
        target_va = int(raw_target, 0) if isinstance(raw_target, str) else int(raw_target)
    except (TypeError, ValueError):
        return None
    function = await _inspect_function_via_mcp(session, target_va, image_base, target_func_name)
    if function is None:
        return None
    if not generate_func_sig:
        function.pop("func_sig", None)
    function.update(slot_data)
    return function


LLM_RESULT_SECTIONS = frozenset({"found_vcall", "found_call", "found_funcptr", "found_gv", "found_struct_offset"})
LLM_SPEC_REQUIRED_KEYS = frozenset(
    {
        "symbol_name",
        "prompt_path",
        "reference_yaml_paths",
        "expected_result_sections",
        "dependency_policy",
    }
)
LLM_SPEC_OPTIONAL_KEYS = frozenset({"instruction_rules", "expected_size"})


def _normalize_llm_decompile_specs(specs):
    normalized = {}
    for raw_spec in specs or ():
        if not isinstance(raw_spec, Mapping):
            return None
        keys = set(raw_spec)
        if not LLM_SPEC_REQUIRED_KEYS <= keys or keys - (LLM_SPEC_REQUIRED_KEYS | LLM_SPEC_OPTIONAL_KEYS):
            return None
        symbol_name = raw_spec.get("symbol_name")
        prompt_path = raw_spec.get("prompt_path")
        references = raw_spec.get("reference_yaml_paths")
        sections = raw_spec.get("expected_result_sections")
        policy = raw_spec.get("dependency_policy")
        if (
            not isinstance(symbol_name, str)
            or not symbol_name
            or symbol_name in normalized
            or not isinstance(prompt_path, str)
            or not prompt_path
            or not isinstance(references, (tuple, list))
            or not references
            or any(not isinstance(value, str) or not value for value in references)
            or not isinstance(sections, (tuple, list, set))
            or not sections
            or any(value not in LLM_RESULT_SECTIONS for value in sections)
            or not isinstance(policy, Mapping)
            or not policy
        ):
            return None
        if any(
            not isinstance(name, str) or not name or not isinstance(value, str) or value not in {"required", "optional"}
            for name, value in policy.items()
        ):
            return None
        policy_keys = [name.casefold() for name in policy]
        if len(set(policy_keys)) != len(policy_keys):
            return None
        spec = {
            "symbol_name": symbol_name,
            "prompt_path": prompt_path,
            "reference_yaml_paths": list(dict.fromkeys(references)),
            "expected_result_sections": list(dict.fromkeys(sections)),
            "dependency_policy": dict(policy),
        }
        rules = raw_spec.get("instruction_rules")
        if rules is not None:
            if not isinstance(rules, (tuple, list)) or not rules:
                return None
            normalized_rules = []
            for rule in rules:
                if not isinstance(rule, Mapping) or set(rule) != {"regex", "text"}:
                    return None
                regex = rule.get("regex")
                text = rule.get("text")
                if not isinstance(regex, str) or not regex or not isinstance(text, str) or not text:
                    return None
                try:
                    re.compile(regex)
                except re.error:
                    return None
                normalized_rules.append({"regex": regex, "text": text})
            spec["instruction_rules"] = normalized_rules
        expected_size = raw_spec.get("expected_size")
        if expected_size is not None:
            if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size <= 0:
                return None
            spec["expected_size"] = expected_size
        normalized[symbol_name] = spec
    return normalized


DEFAULT_REFERENCE_GAMEVER = "hl-10210"
REFERENCE_RESOURCE_ROOT = Path(__file__).resolve().parent / "ida_preprocessor_scripts" / "references"


def _reference_gamever():
    return validated_tag(os.environ.get("GSVIBE_REFERENCE_GAMEVER", DEFAULT_REFERENCE_GAMEVER))


def _resolve_llm_template(value, new_binary_dir, platform, *, gamever=None):
    module_name = Path(new_binary_dir).resolve().name
    resolved_gamever = gamever if gamever is not None else Path(new_binary_dir).resolve().parent.name
    return (
        str(value)
        .replace("{platform}", platform)
        .replace("{module_name}", module_name)
        .replace("{module}", module_name)
        .replace("{gamever}", resolved_gamever)
    )


def _resolve_preprocessor_resource(value, new_binary_dir, platform):
    path = Path(_resolve_llm_template(value, new_binary_dir, platform))
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / "ida_preprocessor_scripts" / path
    return path.resolve()


def _confine_reference_resource(path):
    resolved_root = Path(REFERENCE_RESOURCE_ROOT).resolve()
    resolved_path = Path(path).resolve()
    if not resolved_path.is_relative_to(resolved_root):
        raise ValueError(f"Reference resource path is outside reference root: {resolved_path}")
    return resolved_path


def _resolve_reference_resource(value, new_binary_dir, platform):
    text = str(value)
    current_path = _resolve_preprocessor_resource(text, new_binary_dir, platform)
    if "{gamever}" not in text:
        return current_path
    current_path = _confine_reference_resource(current_path)
    if current_path.is_file():
        return current_path
    fallback_text = text.replace("{gamever}", _reference_gamever())
    return _confine_reference_resource(_resolve_preprocessor_resource(fallback_text, new_binary_dir, platform))


def _index_llm_inputs(values):
    indexed = {}
    for value in values or ():
        try:
            path = Path(value).resolve()
        except (TypeError, OSError):
            return None
        indexed.setdefault(path.name.casefold(), []).append(path)
    return indexed


def _prepare_llm_dependency_contract(spec, llm_config, new_binary_dir, platform):
    if spec is None or not isinstance(llm_config, Mapping):
        return None
    expected_inputs = _index_llm_inputs(llm_config.get("_expected_inputs"))
    optional_inputs = _index_llm_inputs(llm_config.get("_optional_inputs"))
    if expected_inputs is None or optional_inputs is None:
        return None
    if any(len(paths) != 1 for paths in (*expected_inputs.values(), *optional_inputs.values())):
        return None
    if set(expected_inputs) & set(optional_inputs):
        return None
    references = []
    inferred_dependencies = {}
    for reference_value in spec["reference_yaml_paths"]:
        reference_path = _resolve_reference_resource(reference_value, new_binary_dir, platform)
        reference_payload = _load_yaml_mapping(reference_path)
        if (
            not reference_payload
            or set(reference_payload) != {"func_name", "func_va", "disasm_code", "procedure"}
            or not isinstance(reference_payload.get("func_va"), (str, int))
            or not isinstance(reference_payload.get("disasm_code"), str)
            or not reference_payload["disasm_code"].strip()
            or not isinstance(reference_payload.get("procedure"), str)
        ):
            return None
        func_name = reference_payload.get("func_name")
        if not isinstance(func_name, str) or not func_name:
            return None
        artifact_name = f"{func_name}.{platform}.yaml"
        dependency_key = artifact_name.casefold()
        if dependency_key in inferred_dependencies:
            return None
        inferred_dependencies[dependency_key] = artifact_name
        references.append((reference_path, reference_payload, func_name))
    resolved_policy = {}
    for template, policy in spec["dependency_policy"].items():
        artifact_name = Path(_resolve_llm_template(template, new_binary_dir, platform)).name
        artifact_key = artifact_name.casefold()
        if artifact_key in resolved_policy:
            return None
        resolved_policy[artifact_key] = policy
    if set(resolved_policy) != set(inferred_dependencies):
        return None
    for _reference_path, _reference_payload, func_name in references:
        key = f"{func_name}.{platform}.yaml".casefold()
        policy = resolved_policy[key]
        source = expected_inputs if policy == "required" else optional_inputs
        other = optional_inputs if policy == "required" else expected_inputs
        if key in other or len(source.get(key, ())) != 1:
            return None
    return {
        "expected_inputs": expected_inputs,
        "optional_inputs": optional_inputs,
        "references": references,
        "resolved_policy": resolved_policy,
    }


def _prepare_llm_context(spec, llm_config, new_binary_dir, platform, *, dependencies_only=False):
    contract = _prepare_llm_dependency_contract(spec, llm_config, new_binary_dir, platform)
    if contract is None or dependencies_only:
        return contract
    expected_inputs = contract["expected_inputs"]
    optional_inputs = contract["optional_inputs"]
    references = contract["references"]
    resolved_policy = contract["resolved_policy"]
    active_references = []
    reference_paths = []
    targets = []
    for reference_path, reference_payload, func_name in references:
        artifact_name = f"{func_name}.{platform}.yaml"
        key = artifact_name.casefold()
        policy = resolved_policy[key]
        source = expected_inputs if policy == "required" else optional_inputs
        current_payload = _load_yaml_mapping(source[key][0])
        if not current_payload or current_payload.get("func_va") is None:
            if policy == "optional":
                continue
            return None
        try:
            target_ea = _parse_int(current_payload["func_va"], "func_va")
        except SymbolArtifactError:
            if policy == "optional":
                continue
            return None
        active_references.append((reference_path, reference_payload, func_name))
        reference_paths.append(str(reference_path))
        targets.append((reference_payload, target_ea))
    if not targets:
        return None
    prompt_path = _resolve_preprocessor_resource(spec["prompt_path"], new_binary_dir, platform)
    try:
        prompt_template = prompt_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if not prompt_template.strip():
        return None
    model = str(llm_config.get("model") or "").strip()
    if not model:
        return None
    return {
        "targets": targets,
        "prompt_template": prompt_template,
        "prompt_path": str(prompt_path),
        "reference_yaml_paths": reference_paths,
        "reference_items": [reference_payload for _path, reference_payload, _func_name in active_references],
        "model": model,
        "temperature": llm_config.get("temperature"),
        "effort": llm_config.get("effort"),
        "api_key": llm_config.get("api_key"),
        "base_url": llm_config.get("base_url"),
        "fake_as": llm_config.get("fake_as"),
        "max_retries": llm_config.get("max_retries"),
        "retry_initial_delay": llm_config.get("retry_initial_delay"),
        "retry_backoff_factor": llm_config.get("retry_backoff_factor"),
        "retry_max_delay": llm_config.get("retry_max_delay"),
    }


_INSPECT_LLM_INSTRUCTION_PY_EVAL = r"""
import ida_funcs, ida_lines, ida_segment, ida_ua, idaapi, idautils, idc, json
ea = EA_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
insn = ida_ua.insn_t()
size = ida_ua.decode_insn(insn, ea)
func = ida_funcs.get_func(ea)
operand_targets = []
displacements = []
operand_offsets = []
if size:
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        operand_offsets.append(int(op.offb or 0))
        if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
            operand_targets.append(int(op.addr))
        elif op.type == ida_ua.o_imm and ida_segment.getseg(int(op.value)) is not None:
            operand_targets.append(int(op.value))
        elif op.type == ida_ua.o_displ:
            displacements.append(int(op.addr) & 0xFFFFFFFF)
        elif op.type == ida_ua.o_phrase:
            displacements.append(0)
result = json.dumps({
    'pointer_size': pointer_size,
    'size': int(size or 0),
    'func_start': None if func is None else hex(int(func.start_ea)),
    'func_end': None if func is None else hex(int(func.end_ea)),
    'line': ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '').split(';', 1)[0].strip(),
    'mnemonic': idc.print_insn_mnem(ea) or '',
    'code_refs': [hex(int(value)) for value in idautils.CodeRefsFrom(ea, 0)],
    'data_refs': [hex(int(value)) for value in idautils.DataRefsFrom(ea)],
    'operand_targets': [hex(value) for value in operand_targets],
    'displacements': [hex(value) for value in displacements],
    'operand_offsets': operand_offsets,
})
"""


async def _export_llm_function(session, ea):
    code = (
        build_function_detail_export_py_eval(int(ea)).rstrip()
        + "\n"
        + textwrap.dedent(
            """
            payload = json.loads(result)
            import idaapi
            func = ida_funcs.get_func(func_ea)
            payload.update({
                'pointer_size': 8 if idaapi.inf_is_64bit() else 4,
                'func_start': payload.get('func_va'),
                'func_end': None if func is None else hex(int(func.end_ea)),
                'chunk_ranges': [] if func is None else [
                    [hex(int(start_ea)), hex(int(end_ea))]
                    for start_ea, end_ea in _collect_chunk_ranges(func)
                ],
            })
            result = json.dumps(payload)
            """
        ).strip()
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    if isinstance(payload, Mapping) and isinstance(payload.get("function"), Mapping):
        function = dict(payload["function"])
        function["pointer_size"] = payload.get("pointer_size")
        payload = function
    if (
        not isinstance(payload, Mapping)
        or payload.get("pointer_size") != 4
        or not isinstance(payload.get("disasm_code"), str)
        or not payload["disasm_code"].strip()
        or not isinstance(payload.get("procedure"), str)
    ):
        return None
    return dict(payload)


async def _inspect_llm_instruction(session, ea):
    try:
        value = _parse_int(ea, "insn_va")
    except SymbolArtifactError:
        return None
    code = _INSPECT_LLM_INSTRUCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(value))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    if not isinstance(payload, Mapping) or payload.get("pointer_size") != 4 or not payload.get("size"):
        return None
    return dict(payload)


_RESOLVE_JMP_THUNK_PY_EVAL = r"""
import ida_funcs, ida_ua, idc, json
current_ea = EA_PLACEHOLDER
resolved_ea = current_ea
visited = set()
for _ in range(8):
    if current_ea in visited:
        break
    visited.add(current_ea)
    func = ida_funcs.get_func(current_ea)
    if func is None or int(func.start_ea) != current_ea:
        break
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, current_ea) <= 0:
        break
    if (idc.print_insn_mnem(current_ea) or '').strip().lower() != 'jmp':
        break
    if insn.ops[0].type != ida_ua.o_near:
        break
    target_ea = int(insn.ops[0].addr)
    target_func = ida_funcs.get_func(target_ea)
    if target_func is None or int(target_func.start_ea) != target_ea:
        break
    resolved_ea = target_ea
    current_ea = target_ea
result = json.dumps({'func_va': hex(resolved_ea)})
"""


async def _resolve_jmp_thunk_target_via_mcp(session, func_va, debug=False):
    try:
        func_va_int = _parse_int(func_va, "func_va")
        code = _RESOLVE_JMP_THUNK_PY_EVAL.replace("EA_PLACEHOLDER", str(func_va_int))
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
        resolved_va = _parse_int(payload.get("func_va"), "func_va") if isinstance(payload, Mapping) else None
    except Exception:  # noqa: BLE001 - MCP tool failures and payload parsing must fail closed.
        return None
    if resolved_va is None:
        return None
    if debug and resolved_va != func_va_int:
        print(f"    Preprocess: resolved jmp thunk {hex(func_va_int)} -> {hex(resolved_va)}")
    return resolved_va


def _build_llm_instruction_validations(symbol_names, specs):
    return {
        symbol_name: {
            "instruction_rules": specs[symbol_name].get("instruction_rules") or [],
            "expected_size": specs[symbol_name].get("expected_size"),
        }
        for symbol_name in symbol_names
    }


async def _call_llm_for_targets(
    *,
    session,
    symbol_names,
    specs,
    context,
    platform,
    new_binary_dir,
    debug=False,
):
    exported_targets = []
    target_ranges = []
    for _reference, target_ea in context["targets"]:
        exported = await _export_llm_function(session, target_ea)
        if not exported:
            return _empty_llm_decompile_result(), []
        exported_ranges = []
        for raw_range in exported.get("chunk_ranges") or ():
            if not isinstance(raw_range, (tuple, list)) or len(raw_range) != 2:
                return _empty_llm_decompile_result(), []
            try:
                exported_ranges.append((_parse_int(raw_range[0], "chunk_start"), _parse_int(raw_range[1], "chunk_end")))
            except SymbolArtifactError:
                return _empty_llm_decompile_result(), []
        if not exported_ranges:
            try:
                exported_ranges.append(
                    (_parse_int(exported["func_start"], "func_start"), _parse_int(exported["func_end"], "func_end"))
                )
            except (KeyError, SymbolArtifactError):
                return _empty_llm_decompile_result(), []
        if any(start >= end for start, end in exported_ranges):
            return _empty_llm_decompile_result(), []
        target_ranges.extend(exported_ranges)
        exported_targets.append(exported)
    reference_blocks, target_blocks = render_llm_decompile_blocks(context["reference_items"], exported_targets)
    expected_sections = {
        symbol_name: list(specs[symbol_name]["expected_result_sections"]) for symbol_name in symbol_names
    }
    result = await call_llm_decompile(
        model=context["model"],
        symbol_name_list=symbol_names,
        expected_result_sections=expected_sections,
        instruction_validations=_build_llm_instruction_validations(symbol_names, specs),
        disasm_code=exported_targets[0].get("disasm_code", ""),
        target_disasm_codes=[target.get("disasm_code", "") for target in exported_targets],
        procedure=exported_targets[0].get("procedure", ""),
        reference_blocks=reference_blocks,
        target_blocks=target_blocks,
        prompt_template=context["prompt_template"],
        platform=platform,
        new_binary_dir=new_binary_dir,
        temperature=context.get("temperature"),
        effort=context.get("effort"),
        api_key=context.get("api_key"),
        base_url=context.get("base_url"),
        fake_as=context.get("fake_as"),
        max_retries=context.get("max_retries"),
        retry_initial_delay=context.get("retry_initial_delay"),
        retry_backoff_factor=context.get("retry_backoff_factor"),
        retry_max_delay=context.get("retry_max_delay"),
        debug=debug,
    )
    return result, target_ranges


def _build_struct_member_symbol_name(struct_name, member_name):
    struct_name = str(struct_name or "").strip()
    member_name = str(member_name or "").strip()
    if not struct_name or not member_name:
        return None
    return f"{struct_name}_{member_name}".replace(".", "_")


def _resolve_struct_member_entry_names(
    expected_struct_name,
    expected_member_name,
    entry_struct_name,
    entry_member_name,
):
    if entry_struct_name != expected_struct_name:
        return None
    expected_symbol_name = _build_struct_member_symbol_name(expected_struct_name, expected_member_name)
    entry_symbol_name = _build_struct_member_symbol_name(entry_struct_name, entry_member_name)
    if expected_symbol_name is None or entry_symbol_name != expected_symbol_name:
        return None
    return expected_struct_name, expected_member_name


def _entry_identity_matches(entry, symbol_name, category, section):
    field = {
        "func": "func_name",
        "vfunc": "func_name",
        "gv": "gv_name",
        "structmember": None,
    }[category]
    if section == "found_funcptr":
        field = "funcptr_name"
    if field is not None:
        return entry.get(field) == symbol_name
    return _build_struct_member_symbol_name(entry.get("struct_name"), entry.get("member_name")) == symbol_name


def _llm_entry_instruction_is_valid(entry, detail, target_ranges, rules):
    try:
        insn_va = _parse_int(entry.get("insn_va"), "insn_va")
        func_start = _parse_int(detail.get("func_start"), "func_start")
    except SymbolArtifactError:
        return False
    if not any(start <= insn_va < end for start, end in target_ranges) or not any(
        start == func_start for start, _ in target_ranges
    ):
        return False
    line = re.split(r"\s;", str(detail.get("line") or ""), maxsplit=1)[0].strip()
    return not rules or any(re.fullmatch(rule["regex"], line) is not None for rule in rules)


async def _preprocess_llm_target(
    *,
    session,
    symbol_name,
    category,
    spec,
    llm_config,
    new_binary_dir,
    platform,
    image_base,
    desired_fields,
    vtable_name=None,
    expected_struct_name=None,
    expected_member_name=None,
    llm_result=None,
    target_ranges=None,
    debug=False,
):
    result = llm_result
    if result is None:
        context = _prepare_llm_context(spec, llm_config, new_binary_dir, platform)
        if context is None:
            return None
        result, target_ranges = await _call_llm_for_targets(
            session=session,
            symbol_names=[symbol_name],
            specs={symbol_name: spec},
            context=context,
            platform=platform,
            new_binary_dir=new_binary_dir,
            debug=debug,
        )
    if not isinstance(result, Mapping) or not target_ranges:
        return None
    rules = spec.get("instruction_rules") or ()

    section_order = {
        "func": ("found_call", "found_funcptr"),
        "vfunc": ("found_vcall", "found_funcptr"),
        "gv": ("found_gv",),
        "structmember": ("found_struct_offset",),
    }[category]
    for section in section_order:
        if section not in result:
            continue
        for entry in result[section]:
            if not isinstance(entry, Mapping) or not _entry_identity_matches(entry, symbol_name, category, section):
                continue
            detail = await _inspect_llm_instruction(session, entry.get("insn_va"))
            if detail is None or not _llm_entry_instruction_is_valid(entry, detail, target_ranges, rules):
                continue
            if category == "func":
                targets = detail.get("code_refs") if section == "found_call" else detail.get("operand_targets")
                if not isinstance(targets, list) or len(set(targets)) != 1:
                    continue
                target_va = _parse_int(targets[0], "function target")
                if section == "found_call" and "func_sig_resolve_jmp_thunk" in desired_fields:
                    target_va = await _resolve_jmp_thunk_target_via_mcp(session, target_va, debug=debug)
                    if target_va is None:
                        continue
                function = await _inspect_function_via_mcp(session, target_va, image_base, symbol_name)
                if function:
                    return function
            elif category == "vfunc":
                if section == "found_vcall":
                    try:
                        offset = _parse_int(entry.get("vfunc_offset"), "vfunc_offset")
                    except SymbolArtifactError:
                        continue
                    if offset < 0 or offset % 4 or hex(offset) not in set(detail.get("displacements") or ()):
                        continue
                    vtable = _load_yaml_mapping(_vtable_yaml_path(new_binary_dir, vtable_name, platform))
                    if not vtable and not _is_vtable_artifact_stem(vtable_name):
                        vtable = await preprocess_vtable_via_mcp(
                            session, vtable_name, image_base, platform, symbol_aliases=None
                        )
                    entries = (vtable or {}).get("vtable_entries") or {}
                    raw_target = entries.get(offset // 4, entries.get(str(offset // 4)))
                    if raw_target is None:
                        continue
                    function = await _inspect_function_via_mcp(
                        session, _parse_int(raw_target, "vtable entry"), image_base, symbol_name
                    )
                    if not function:
                        continue
                    function.update(
                        {
                            "vtable_name": vtable_name,
                            "vfunc_offset": hex(offset),
                            "vfunc_index": offset // 4,
                            "vfunc_sig": function.get("func_sig"),
                        }
                    )
                    if "func_sig" not in desired_fields:
                        function.pop("func_sig", None)
                    return function
                targets = detail.get("operand_targets")
                if not isinstance(targets, list) or len(set(targets)) != 1:
                    continue
                function = await _inspect_function_via_mcp(
                    session, _parse_int(targets[0], "function target"), image_base, symbol_name
                )
                if function:
                    enriched = _enrich_vfunc_from_vtable(function, vtable_name, new_binary_dir, platform)
                    if enriched:
                        enriched["vfunc_sig"] = enriched.get("func_sig")
                        return enriched
            elif category == "gv":
                targets = list(dict.fromkeys((detail.get("data_refs") or []) + (detail.get("operand_targets") or [])))
                if len(targets) != 1:
                    continue
                function = await _inspect_function_via_mcp(
                    session, _parse_int(detail["func_start"], "func_start"), image_base, "__llm_anchor"
                )
                if not function or not function.get("func_sig"):
                    continue
                gv_va = _parse_int(targets[0], "gv target")
                insn_va = _parse_int(entry["insn_va"], "insn_va")
                return {
                    "gv_name": symbol_name,
                    "gv_va": hex(gv_va),
                    "gv_rva": hex(gv_va - int(image_base)),
                    "gv_sig": function["func_sig"],
                    "gv_sig_va": function["func_va"],
                    "gv_inst_offset": insn_va - _parse_int(function["func_va"], "func_va"),
                    "gv_inst_length": detail["size"],
                    "gv_inst_disp": next((value for value in detail.get("operand_offsets") or () if value), 0),
                }
            else:
                resolved_names = None
                if expected_struct_name and expected_member_name:
                    resolved_names = _resolve_struct_member_entry_names(
                        expected_struct_name,
                        expected_member_name,
                        str(entry.get("struct_name") or "").strip(),
                        str(entry.get("member_name") or "").strip(),
                    )
                    if resolved_names is None:
                        continue
                resolved_struct_name, resolved_member_name = resolved_names or (
                    entry["struct_name"],
                    entry["member_name"],
                )
                try:
                    offset = _parse_int(entry.get("offset"), "offset")
                except SymbolArtifactError:
                    continue
                if hex(offset) not in set(detail.get("displacements") or ()):
                    continue
                if spec.get("expected_size") is not None:
                    try:
                        entry_size = _parse_int(entry.get("size"), "size")
                    except SymbolArtifactError:
                        continue
                    if entry_size != spec["expected_size"]:
                        continue
                function = await _inspect_function_via_mcp(
                    session, _parse_int(detail["func_start"], "func_start"), image_base, "__llm_anchor"
                )
                if not function or not function.get("func_sig"):
                    continue
                insn_va = _parse_int(entry["insn_va"], "insn_va")
                payload = {
                    "struct_name": resolved_struct_name,
                    "member_name": resolved_member_name,
                    "offset": hex(offset),
                    "offset_sig": function["func_sig"],
                    "offset_sig_disp": insn_va - _parse_int(function["func_va"], "func_va"),
                }
                if entry.get("size") is not None:
                    payload["size"] = entry["size"]
                return payload
    return None


def _llm_spec_matches_target(spec, category):
    if not isinstance(spec, Mapping):
        return False
    allowed_sections = {
        "func": {"found_call", "found_funcptr"},
        "vfunc": {"found_vcall", "found_funcptr"},
        "gv": {"found_gv"},
        "structmember": {"found_struct_offset"},
    }[category]
    sections = set(spec.get("expected_result_sections") or ())
    if not sections or not sections <= allowed_sections:
        return False
    return category == "structmember" or spec.get("expected_size") is None


def _candidate_satisfies_field_spec(candidate, field_spec):
    if not isinstance(candidate, Mapping) or not isinstance(field_spec, Mapping):
        return False
    if candidate.get("_pointer_size", 4) != 4:
        return False
    available_fields = {field for field, value in candidate.items() if value is not None}
    available_fields.update((field_spec.get("generation_options") or {}).keys())
    optional_fields = set(field_spec.get("optional_fields") or ())
    required_fields = {field for field in field_spec.get("fields") or () if field not in optional_fields}
    return required_fields <= available_fields


async def preprocess_common_skill(
    session,
    expected_outputs,
    old_yaml_map=None,
    new_binary_dir=None,
    platform="windows",
    image_base=0,
    func_names=None,
    gv_names=None,
    patch_names=None,
    struct_member_names=None,
    vtable_class_names=None,
    inherit_vfuncs=None,
    func_xrefs=None,
    func_vtable_relations=None,
    generate_yaml_desired_fields=None,
    llm_decompile_specs=None,
    llm_config=None,
    mangled_class_names=None,
    debug=False,
    canonical_vtable_symbols=None,
):
    """GoldSrc x86 implementation of the CS2 finder/helper API."""

    desired = _desired_fields_map(generate_yaml_desired_fields)
    if desired is None:
        return False
    if platform not in {"windows", "linux"} or new_binary_dir is None:
        return False
    processed: set[str] = set()

    def emit(symbol_name, category, candidate, output=None):
        if not isinstance(candidate, Mapping):
            return False
        candidate = dict(candidate)
        pointer_size = candidate.pop("_pointer_size", 4)
        if pointer_size != 4:
            return False
        field_spec = desired.get(symbol_name)
        if field_spec is None:
            return False
        for field, value in field_spec["generation_options"].items():
            candidate.setdefault(field, value)
        fields = field_spec["fields"]
        required_fields = [field for field in fields if field not in field_spec["optional_fields"]]
        if any(field not in candidate for field in required_fields):
            return False
        target = output or _output_for_symbol(expected_outputs, symbol_name)
        if target is None:
            return False
        payload = {field: candidate[field] for field in fields if field in candidate}
        if category in {"func", "vfunc"}:
            write_func_yaml(target, payload)
        elif category == "gv":
            write_gv_yaml(target, payload)
        elif category == "patch":
            write_patch_yaml(target, payload)
        elif category == "vtable":
            write_vtable_yaml(target, payload)
        elif category == "structmember":
            write_struct_offset_yaml(target, payload)
        else:
            return False
        processed.add(symbol_name)
        return True

    xref_by_name = _normalize_func_xref_specs(func_xrefs)
    if xref_by_name is None:
        return False
    try:
        vtable_by_name = dict(func_vtable_relations or ())
    except (TypeError, ValueError):
        return False
    if len(vtable_by_name) != len(func_vtable_relations or ()) or any(
        not isinstance(name, str) or not name or not isinstance(vtable, str) or not vtable
        for name, vtable in vtable_by_name.items()
    ):
        return False
    llm_specs = _normalize_llm_decompile_specs(llm_decompile_specs)
    if llm_specs is None:
        return False
    function_targets = list(func_names or ())
    for xref_name in xref_by_name:
        if xref_name not in function_targets:
            function_targets.append(xref_name)
    if any(
        _output_for_symbol(expected_outputs, func_name) is None or desired.get(func_name) is None
        for func_name in function_targets
    ):
        return False

    target_categories = {name: ("vfunc" if name in vtable_by_name else "func") for name in function_targets}
    target_categories.update({name: "gv" for name in gv_names or ()})
    target_categories.update({name: "structmember" for name in struct_member_names or ()})
    if set(llm_specs) - set(target_categories) or any(
        not _llm_spec_matches_target(spec, target_categories[name]) for name, spec in llm_specs.items()
    ):
        return False

    for symbol_name, spec in llm_specs.items():
        contract = _prepare_llm_context(
            spec,
            llm_config,
            new_binary_dir,
            platform,
            dependencies_only=True,
        )
        if contract is None:
            return False

    for class_name in vtable_class_names or ():
        output = _output_for_symbol(expected_outputs, class_name) or _output_for_symbol(
            expected_outputs, f"{class_name}_vtable"
        )
        aliases = (mangled_class_names or {}).get(class_name) if isinstance(mangled_class_names, Mapping) else None
        candidate = await preprocess_vtable_via_mcp(
            session,
            class_name,
            image_base,
            platform,
            debug=debug,
            symbol_aliases=aliases,
        )
        if candidate is not None and isinstance(canonical_vtable_symbols, Mapping):
            candidate["vtable_symbol"] = canonical_vtable_symbols.get(class_name, candidate["vtable_symbol"])
        if not emit(class_name, "vtable", candidate, output):
            return False

    async def try_function_fast_path(func_name):
        output = _output_for_symbol(expected_outputs, func_name)
        field_spec = desired.get(func_name)
        if output is None or field_spec is None:
            return None
        generation_options = field_spec["generation_options"]
        candidate = await preprocess_func_sig_via_mcp(
            session,
            output,
            _old_path_for_output(old_yaml_map, output),
            image_base,
            new_binary_dir,
            platform,
            func_name=func_name,
            debug=debug,
            mangled_class_names=mangled_class_names,
            allow_func_sig_across_function_boundary=generation_options.get(
                "func_sig_allow_across_function_boundary", False
            ),
        )
        xref_spec = xref_by_name.get(func_name)
        if candidate is None and xref_spec is not None:
            candidate = await preprocess_func_xrefs_via_mcp(
                session=session,
                func_name=func_name,
                xref_strings=xref_spec.get("xref_strings"),
                xref_gvs=xref_spec.get("xref_gvs"),
                xref_signatures=xref_spec.get("xref_signatures"),
                xref_funcs=xref_spec.get("xref_funcs"),
                exclude_funcs=xref_spec.get("exclude_funcs"),
                exclude_strings=xref_spec.get("exclude_strings"),
                exclude_gvs=xref_spec.get("exclude_gvs"),
                exclude_signatures=xref_spec.get("exclude_signatures"),
                new_binary_dir=new_binary_dir,
                platform=platform,
                image_base=image_base,
                vtable_class=vtable_by_name.get(func_name),
                allow_func_sig_across_function_boundary=generation_options.get(
                    "func_sig_allow_across_function_boundary", False
                ),
                debug=debug,
                xref_floats=xref_spec.get("xref_floats"),
                exclude_floats=xref_spec.get("exclude_floats"),
                inline_alias=xref_spec.get("inline_alias"),
                exclude_callees=xref_spec.get("exclude_callees"),
            )
        if candidate is not None and generation_options.get("func_sig_resolve_jmp_thunk"):
            try:
                candidate_va = _parse_int(candidate.get("func_va"), "func_va")
            except SymbolArtifactError:
                candidate = None
                candidate_va = None
            resolved_va = (
                await _resolve_jmp_thunk_target_via_mcp(
                    session,
                    candidate_va,
                    debug=debug,
                )
                if candidate_va is not None
                else None
            )
            if resolved_va is None:
                candidate = None
            elif resolved_va != candidate_va:
                candidate = await _inspect_function_via_mcp(session, resolved_va, image_base, func_name)
                if candidate is not None and generation_options.get("func_sig_allow_across_function_boundary"):
                    candidate["func_sig_allow_across_function_boundary"] = True
        if candidate is not None and func_name in vtable_by_name:
            candidate = dict(candidate)
            vtable_name = vtable_by_name[func_name]
            if "vfunc_offset" not in candidate or "vfunc_index" not in candidate:
                unenriched_candidate = candidate
                try:
                    candidate = _enrich_vfunc_from_vtable(
                        unenriched_candidate,
                        vtable_name,
                        new_binary_dir,
                        platform,
                    )
                except (KeyError, TypeError, ValueError, SymbolArtifactError):
                    candidate = None
                if candidate is None and not _is_vtable_artifact_stem(vtable_name):
                    live_vtable = await preprocess_vtable_via_mcp(
                        session,
                        vtable_name,
                        image_base,
                        platform,
                        debug=debug,
                        symbol_aliases=(mangled_class_names or {}).get(vtable_name)
                        if isinstance(mangled_class_names, Mapping)
                        else None,
                    )
                    try:
                        candidate = _enrich_vfunc_from_vtable_data(
                            unenriched_candidate,
                            vtable_name,
                            live_vtable,
                        )
                    except (KeyError, TypeError, ValueError, SymbolArtifactError):
                        candidate = None
            elif "vtable_name" in field_spec["fields"]:
                candidate["vtable_name"] = vtable_name
            if candidate is not None and "vfunc_sig" in field_spec["fields"] and candidate.get("func_sig"):
                candidate.setdefault("vfunc_sig", candidate["func_sig"])
        if not _candidate_satisfies_field_spec(candidate, field_spec):
            candidate = None
        return candidate

    function_fast_results = {}
    function_fast_attempted = {}
    for func_name in function_targets:
        can_probe = _can_probe_future_func_fast_path(
            func_name=func_name,
            func_xrefs_map=xref_by_name,
            new_binary_dir=new_binary_dir,
            platform=platform,
        )
        function_fast_attempted[func_name] = can_probe
        function_fast_results[func_name] = await try_function_fast_path(func_name) if can_probe else None

    gv_fast_results = {}
    for gv_name in gv_names or ():
        output = _output_for_symbol(expected_outputs, gv_name)
        if output is None or desired.get(gv_name) is None:
            return False
        candidate = await preprocess_gv_sig_via_mcp(
            session,
            output,
            _old_path_for_output(old_yaml_map, output),
            image_base,
            new_binary_dir,
            platform,
            debug,
        )
        gv_fast_results[gv_name] = candidate if _candidate_satisfies_field_spec(candidate, desired[gv_name]) else None

    struct_fast_results = {}
    struct_old_metadata = {}
    for member_name in struct_member_names or ():
        output = _output_for_symbol(expected_outputs, member_name)
        if output is None or desired.get(member_name) is None:
            return False
        old_path = _old_path_for_output(old_yaml_map, output)
        old_data = _load_yaml_mapping(old_path) or {}
        struct_old_metadata[member_name] = (
            old_data.get("struct_name"),
            old_data.get("member_name"),
        )
        candidate = await preprocess_struct_offset_sig_via_mcp(
            session,
            output,
            old_path,
            image_base,
            new_binary_dir,
            platform,
            debug,
        )
        struct_fast_results[member_name] = (
            candidate if _candidate_satisfies_field_spec(candidate, desired[member_name]) else None
        )

    unresolved_symbols = [
        name
        for name, candidate in function_fast_results.items()
        if function_fast_attempted.get(name) and candidate is None and name in llm_specs
    ]
    unresolved_symbols.extend(
        name
        for name, candidate in {**gv_fast_results, **struct_fast_results}.items()
        if candidate is None and name in llm_specs
    )
    request_groups = {}
    for symbol_name in unresolved_symbols:
        context = _prepare_llm_context(llm_specs[symbol_name], llm_config, new_binary_dir, platform)
        if context is None:
            continue
        cache_key = _build_llm_decompile_request_cache_key(context)
        if cache_key is None:
            continue
        group = request_groups.setdefault(cache_key, {"context": context, "symbol_names": []})
        group["symbol_names"].append(symbol_name)

    llm_batch_results = {}
    for group in request_groups.values():
        symbol_names = group["symbol_names"]
        result, target_ranges = await _call_llm_for_targets(
            session=session,
            symbol_names=symbol_names,
            specs=llm_specs,
            context=group["context"],
            platform=platform,
            new_binary_dir=new_binary_dir,
            debug=debug,
        )
        for symbol_name in symbol_names:
            llm_batch_results[symbol_name] = (result, target_ranges)

    for func_name in function_targets:
        output = _output_for_symbol(expected_outputs, func_name)
        if output is None:
            return False
        field_spec = desired.get(func_name)
        if field_spec is None:
            return False
        if not function_fast_attempted.get(func_name):
            function_fast_results[func_name] = await try_function_fast_path(func_name)
            function_fast_attempted[func_name] = True
        candidate = function_fast_results[func_name]
        if candidate is None:
            if func_name in llm_specs and func_name not in llm_batch_results:
                context = _prepare_llm_context(llm_specs[func_name], llm_config, new_binary_dir, platform)
                if context is not None:
                    llm_batch_results[func_name] = await _call_llm_for_targets(
                        session=session,
                        symbol_names=[func_name],
                        specs=llm_specs,
                        context=context,
                        platform=platform,
                        new_binary_dir=new_binary_dir,
                        debug=debug,
                    )
            llm_result, target_ranges = llm_batch_results.get(func_name, (_empty_llm_decompile_result(), []))
            candidate = await _preprocess_llm_target(
                session=session,
                symbol_name=func_name,
                category="vfunc" if func_name in vtable_by_name else "func",
                spec=llm_specs.get(func_name),
                llm_config=llm_config,
                new_binary_dir=new_binary_dir,
                platform=platform,
                image_base=image_base,
                vtable_name=vtable_by_name.get(func_name),
                desired_fields=field_spec["fields"],
                llm_result=llm_result,
                target_ranges=target_ranges,
                debug=debug,
            )
        if candidate is None:
            return False
        if func_name in vtable_by_name:
            if "vfunc_offset" not in candidate or "vfunc_index" not in candidate:
                unenriched_candidate = candidate
                candidate = _enrich_vfunc_from_vtable(
                    unenriched_candidate, vtable_by_name[func_name], new_binary_dir, platform
                )
                if candidate is None and not _is_vtable_artifact_stem(vtable_by_name[func_name]):
                    live_vtable = await preprocess_vtable_via_mcp(
                        session,
                        vtable_by_name[func_name],
                        image_base,
                        platform,
                        debug=debug,
                        symbol_aliases=(mangled_class_names or {}).get(vtable_by_name[func_name])
                        if isinstance(mangled_class_names, Mapping)
                        else None,
                    )
                    candidate = _enrich_vfunc_from_vtable_data(
                        unenriched_candidate, vtable_by_name[func_name], live_vtable
                    )
            elif "vtable_name" in field_spec["fields"]:
                candidate["vtable_name"] = vtable_by_name[func_name]
        category = "vfunc" if func_name in vtable_by_name else "func"
        if not emit(func_name, category, candidate, output):
            return False

    for raw_spec in inherit_vfuncs or ():
        if not isinstance(raw_spec, (tuple, list)) or len(raw_spec) not in {3, 4}:
            return False
        target_name, inherit_class, base_name = raw_spec[:3]
        generate_sig = bool(raw_spec[3]) if len(raw_spec) == 4 else True
        output = _output_for_symbol(expected_outputs, target_name)
        target_field_spec = desired.get(target_name)
        if target_field_spec is None:
            return False
        fields = set(target_field_spec["fields"])
        slot_only = fields == {"func_name", "vtable_name", "vfunc_offset", "vfunc_index"}
        candidate = await preprocess_index_based_vfunc_via_mcp(
            session,
            target_name,
            output,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            base_name,
            inherit_class,
            generate_func_sig=generate_sig,
            slot_only=slot_only,
            allow_func_sig_across_function_boundary=target_field_spec["generation_options"].get(
                "func_sig_allow_across_function_boundary", False
            ),
            debug=debug,
        )
        if not emit(target_name, "vfunc", candidate, output):
            return False

    for gv_name in gv_names or ():
        output = _output_for_symbol(expected_outputs, gv_name)
        field_spec = desired.get(gv_name)
        if field_spec is None:
            return False
        candidate = gv_fast_results[gv_name]
        if candidate is None:
            llm_result, target_ranges = llm_batch_results.get(gv_name, (_empty_llm_decompile_result(), []))
            candidate = await _preprocess_llm_target(
                session=session,
                symbol_name=gv_name,
                category="gv",
                spec=llm_specs.get(gv_name),
                llm_config=llm_config,
                new_binary_dir=new_binary_dir,
                platform=platform,
                image_base=image_base,
                desired_fields=field_spec["fields"],
                llm_result=llm_result,
                target_ranges=target_ranges,
                debug=debug,
            )
        if not emit(gv_name, "gv", candidate, output):
            return False

    for patch_name in patch_names or ():
        output = _output_for_symbol(expected_outputs, patch_name)
        candidate = await preprocess_patch_via_mcp(
            session,
            output,
            _old_path_for_output(old_yaml_map, output),
            image_base,
            new_binary_dir,
            platform,
            debug,
        )
        if not emit(patch_name, "patch", candidate, output):
            return False

    for member_name in struct_member_names or ():
        output = _output_for_symbol(expected_outputs, member_name)
        field_spec = desired.get(member_name)
        if field_spec is None:
            return False
        candidate = struct_fast_results[member_name]
        if candidate is None:
            expected_struct_name, expected_member_name = struct_old_metadata[member_name]
            llm_result, target_ranges = llm_batch_results.get(member_name, (_empty_llm_decompile_result(), []))
            candidate = await _preprocess_llm_target(
                session=session,
                symbol_name=member_name,
                category="structmember",
                spec=llm_specs.get(member_name),
                llm_config=llm_config,
                new_binary_dir=new_binary_dir,
                platform=platform,
                image_base=image_base,
                desired_fields=field_spec["fields"],
                expected_struct_name=(expected_struct_name.strip() if isinstance(expected_struct_name, str) else None),
                expected_member_name=(expected_member_name.strip() if isinstance(expected_member_name, str) else None),
                llm_result=llm_result,
                target_ranges=target_ranges,
                debug=debug,
            )
        if not emit(member_name, "structmember", candidate, output):
            return False

    return processed == set(desired)
