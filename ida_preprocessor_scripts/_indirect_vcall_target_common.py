"""Resolve a unique x86 indirect virtual-call slot from a known function."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, write_func_yaml


_SCAN_TEMPLATE = r"""
import ida_funcs, ida_ua, idaapi, idautils, json
source_va = SOURCE_VA_PLACEHOLDER
allowed = set(ALLOWED_PLACEHOLDER)
resolve_load_then_branch = RESOLVE_LOAD_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
func = ida_funcs.get_func(source_va)
targets = []
if func is not None and int(func.start_ea) == source_va and pointer_size == 4:
    previous = None
    for ea in idautils.FuncItems(source_va):
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            continue
        mnemonic = insn.get_canon_mnem().lower()
        if mnemonic in allowed:
            op = insn.ops[0]
            offset = None
            if op.type == ida_ua.o_displ:
                offset = int(op.addr) & 0xFFFFFFFF
            elif resolve_load_then_branch and op.type == ida_ua.o_reg and previous is not None:
                prior_ea, prior = previous
                if prior.get_canon_mnem().lower() == 'mov':
                    dst, src = prior.ops[0], prior.ops[1]
                    if dst.type == ida_ua.o_reg and dst.reg == op.reg and src.type == ida_ua.o_displ:
                        offset = int(src.addr) & 0xFFFFFFFF
            if offset is not None and offset % pointer_size == 0:
                targets.append({
                    'source_ea': hex(int(ea)),
                    'source_mnemonic': mnemonic,
                    'vfunc_offset': hex(offset),
                    'vfunc_index': offset // pointer_size,
                })
        previous = (ea, insn)
unique = {}
for target in targets:
    unique[(target['vfunc_offset'], target['vfunc_index'])] = target
result = json.dumps({'pointer_size': pointer_size, 'targets': list(unique.values())})
"""


def _output_path(expected_outputs, target_name, platform):
    expected_name = f"{target_name}.{platform}.yaml"
    matches = [Path(path) for path in expected_outputs or () if Path(path).name == expected_name]
    return matches[0] if len(matches) == 1 else None


def _requested_fields(specs, target_name):
    if not isinstance(specs, list):
        return None
    for name, fields in specs:
        if name == target_name and isinstance(fields, list) and fields:
            return fields
    return None


async def preprocess_indirect_vcall_target_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    source_yaml_stem,
    target_name,
    vtable_name,
    generate_yaml_desired_fields,
    allowed_mnemonics=("call", "jmp"),
    resolve_load_then_branch=False,
    expected_target_count=1,
    debug=False,
):
    """Scan a known function and write one deterministic x86 slot-only vfunc artifact."""

    if expected_target_count != 1 or platform not in {"windows", "linux"}:
        return False
    output = _output_path(expected_outputs, target_name, platform)
    fields = _requested_fields(generate_yaml_desired_fields, target_name)
    if output is None or fields is None:
        return False
    source_path = Path(new_binary_dir) / f"{source_yaml_stem}.{platform}.yaml"
    try:
        source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
        source_va = int(source["func_va"], 0)
    except (OSError, TypeError, ValueError, KeyError, yaml.YAMLError):
        return False
    code = (
        _SCAN_TEMPLATE.replace("SOURCE_VA_PLACEHOLDER", str(source_va))
        .replace("ALLOWED_PLACEHOLDER", json.dumps(list(allowed_mnemonics)))
        .replace("RESOLVE_LOAD_PLACEHOLDER", "True" if resolve_load_then_branch else "False")
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:
        return False
    targets = payload.get("targets") if isinstance(payload, dict) and payload.get("pointer_size") == 4 else None
    if not isinstance(targets, list) or len(targets) != expected_target_count or not isinstance(targets[0], dict):
        return False
    available = {
        "func_name": target_name,
        "vtable_name": vtable_name,
        "vfunc_offset": targets[0].get("vfunc_offset"),
        "vfunc_index": targets[0].get("vfunc_index"),
    }
    if any(field not in available or available[field] is None for field in fields):
        return False
    try:
        write_func_yaml(output, {field: available[field] for field in fields})
    except Exception:
        return False
    if debug:
        print(f"    Preprocess: resolved {target_name} at slot {available['vfunc_index']}")
    return True
