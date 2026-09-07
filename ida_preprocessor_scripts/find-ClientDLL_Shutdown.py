#!/usr/bin/env python3
"""Locate ClientDLL_Shutdown, the client-unload helper.

HL25 inlines this body into ClientDLL_Init. Older GoldSrc keeps a standalone
function: ClientDLL_Init calls it when the client is already loaded, and the
body calls FreeLibrary (or dlclose) plus the blob unload helper.

The locator consumes the ClientDLL_Init artifact and requires exactly one
direct callee that both (1) is larger than the tiny FreeBlob wrapper and
(2) calls FreeLibrary/dlclose. Discovery does not use a byte signature or
old YAML.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNCTION_NAME = "ClientDLL_Shutdown"
OWNER_FUNC_NAME = "ClientDLL_Init"
MIN_SHUTDOWN_SIZE = 0x40

LOCATE_PY = r"""
import ida_funcs
import ida_name
import idaapi
import idautils
import idc
import json
import traceback

CLIENTDLL_INIT_EA = CLIENTDLL_INIT_EA_PLACEHOLDER
MIN_SHUTDOWN_SIZE = MIN_SHUTDOWN_SIZE_PLACEHOLDER

def insn_mnem(ea):
    return (idc.print_insn_mnem(int(ea)) or '').lower()

def call_targets(ea):
    starts = set()
    for xref in idautils.XrefsFrom(int(ea), 0):
        if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
            func = ida_funcs.get_func(int(xref.to))
            starts.add(int(func.start_ea) if func is not None else int(xref.to))
    return starts

def is_unload_import_name(name):
    lowered = (name or '').lower()
    return 'freelibrary' in lowered or 'dlclose' in lowered

def function_calls_unload_import(func):
    for ea in idautils.FuncItems(int(func.start_ea)):
        if insn_mnem(ea) != 'call':
            continue
        names = [idc.generate_disasm_line(int(ea), 0) or '']
        insn = idautils.DecodeInstruction(int(ea))
        if insn is not None:
            op = insn.ops[0]
            if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_near), int(idaapi.o_imm)):
                names.append(ida_name.get_name(int(op.addr if int(op.type) != int(idaapi.o_imm) else op.value)) or '')
        for xref in idautils.XrefsFrom(int(ea), 0):
            names.append(ida_name.get_name(int(xref.to)) or '')
        if any(is_unload_import_name(name) for name in names):
            return True
    return False

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(CLIENTDLL_INIT_EA))
    if owner is None or int(owner.start_ea) != int(CLIENTDLL_INIT_EA):
        raise RuntimeError('ClientDLL_Init is not a function start')
    candidates = []
    rejected = []
    seen = set()
    for ea in idautils.FuncItems(int(owner.start_ea)):
        if insn_mnem(ea) != 'call':
            continue
        for start in call_targets(ea):
            if start in seen:
                continue
            seen.add(start)
            func = ida_funcs.get_func(int(start))
            rec = {
                'ea': hex(int(start)),
                'name': idc.get_func_name(int(start)) or '',
                'size': None if func is None else hex(int(func.end_ea) - int(start)),
            }
            if func is None or int(func.start_ea) != int(start):
                rec['reason'] = 'not a function start'
                rejected.append(rec)
                continue
            size = int(func.end_ea) - int(start)
            rec['unload'] = function_calls_unload_import(func)
            if size >= int(MIN_SHUTDOWN_SIZE) and rec['unload']:
                candidates.append(rec)
            else:
                rec['reason'] = 'too small or no FreeLibrary/dlclose'
                rejected.append(rec)
    if len(candidates) != 1:
        result = json.dumps({
            'error': 'ClientDLL_Shutdown is not unique from ClientDLL_Init callees',
            'owner': hex(int(owner.start_ea)),
            'candidates': candidates,
            'rejected': rejected[:20],
        })
    else:
        start = int(candidates[0]['ea'], 0)
        try:
            ida_name.set_name(start, 'ClientDLL_Shutdown', ida_name.SN_FORCE)
        except Exception:
            pass
        func = ida_funcs.get_func(start)
        result = json.dumps({
            'pointer_size': 4,
            'func_ea': hex(start),
            'func_size': hex(int(func.end_ea) - start) if func else None,
            'owner': hex(int(owner.start_ea)),
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _function_artifact_path(new_binary_dir, platform, func_name):
    return Path(new_binary_dir) / f"{func_name}.{platform}.yaml"


def _function_artifact(new_binary_dir, platform, func_name, image_base):
    artifact = _load_yaml_mapping(_function_artifact_path(new_binary_dir, platform, func_name))
    if not artifact or artifact.get("func_name") != func_name:
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    if func_ea < int(image_base):
        return None
    return artifact, func_ea


def _function_allows_across_boundary(artifact):
    return bool(artifact.get("func_sig_allow_across_function_boundary"))


async def _locate_shutdown(session, clientdll_init_ea):
    code = LOCATE_PY.replace("CLIENTDLL_INIT_EA_PLACEHOLDER", str(int(clientdll_init_ea))).replace(
        "MIN_SHUTDOWN_SIZE_PLACEHOLDER", str(int(MIN_SHUTDOWN_SIZE))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    return payload


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNCTION_NAME)
    if output is None:
        return False
    owner = _function_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner is None:
        if debug:
            print("  find-ClientDLL_Shutdown: missing ClientDLL_Init artifact")
        return False
    owner_data, owner_ea = owner
    owner_function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=_function_allows_across_boundary(owner_data),
    )
    if not owner_function or not owner_function.get("func_sig"):
        if debug:
            print("  find-ClientDLL_Shutdown: failed to verify ClientDLL_Init artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_shutdown(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-ClientDLL_Shutdown: locator failed {located}")
        return False
    try:
        func_ea = int(located["func_ea"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    if func_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, func_ea, image_base, TARGET_FUNCTION_NAME)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session,
            func_ea,
            image_base,
            TARGET_FUNCTION_NAME,
            allow_across_function_boundary=True,
        )
        allow_across = True
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  find-ClientDLL_Shutdown: function inspect failed ea={located.get('func_ea')}")
        return False
    try:
        inspected_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_va != func_ea:
        return False
    if debug:
        print(
            f"  find-ClientDLL_Shutdown: ea={located['func_ea']} size={located.get('func_size')} across={allow_across}"
        )
    payload = {
        "func_name": TARGET_FUNCTION_NAME,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
