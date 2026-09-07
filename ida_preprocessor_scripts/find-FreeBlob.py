#!/usr/bin/env python3
"""Locate FreeBlob, the blob-client unload helper.

HL25 inlines the secure-client unload into ClientDLL_Init:
push footprint; call FreeBlob vs push hModule; call FreeLibrary.

Older GoldSrc keeps that fork in ClientDLL_Shutdown, a direct callee of
ClientDLL_Init. The locator therefore scans ClientDLL_Init and its direct
callees for a call that:

1. is preceded by pushing a global footprint pointer, and
2. targets a small function that FreeLibrary/dlclose-s the dereferenced argument.

Discovery does not use a byte signature, old YAML, or LLM_DECOMPILE.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNCTION_NAME = "FreeBlob"
OWNER_FUNC_NAME = "ClientDLL_Init"

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

CLIENTDLL_INIT_EA = CLIENTDLL_INIT_EA_PLACEHOLDER

def data_address(ea):
    value = int(ea) & 0xFFFFFFFF
    if value < 0x10000:
        return False
    seg = ida_segment.getseg(value)
    if seg is None:
        return False
    perms = int(getattr(seg, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    return not bool(perms & executable)

def insn_mnem(ea):
    return (idc.print_insn_mnem(int(ea)) or '').lower()

def decode(ea):
    return idautils.DecodeInstruction(int(ea))

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

def call_is_unload_import(ea):
    insn = decode(ea)
    if not insn or insn_mnem(ea) != 'call':
        return False
    names = [idc.generate_disasm_line(int(ea), 0) or '']
    for xref in idautils.XrefsFrom(int(ea), 0):
        names.append(ida_name.get_name(int(xref.to)) or '')
        func = ida_funcs.get_func(int(xref.to))
        if func is not None:
            names.append(ida_name.get_name(int(func.start_ea)) or '')
    op = insn.ops[0]
    if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_near), int(idaapi.o_imm)):
        names.append(ida_name.get_name(int(op.addr if int(op.type) != int(idaapi.o_imm) else op.value)) or '')
    return any(is_unload_import_name(name) for name in names)

def previous_head(ea, func):
    prev = ida_bytes.prev_head(int(ea), int(func.start_ea))
    return None if prev == idaapi.BADADDR else int(prev)

def pushes_global(ea):
    insn = decode(ea)
    if not insn or insn_mnem(ea) != 'push':
        return False
    op = insn.ops[0]
    value = None
    if int(op.type) == int(idaapi.o_imm):
        value = int(op.value) & 0xFFFFFFFF
    elif int(op.type) == int(idaapi.o_mem):
        value = int(op.addr) & 0xFFFFFFFF
    return value is not None and data_address(value)

DEREF_MARKERS = (
    b'\x8b\x00',
    b'\x8b\x08',
    b'\x8b\x10',
    b'\x8b\x18',
    b'\x8b\x28',
    b'\x8b\x30',
    b'\x8b\x38',
    b'\xff\x30',
    b'\xff\x31',
    b'\xff\x32',
    b'\xff\x33',
    b'\xff\x36',
    b'\xff\x37',
)

def function_derefs_arg0_and_unloads(func):
    size = int(func.end_ea) - int(func.start_ea)
    if size < 8 or size > 0x30:
        return False
    raw = ida_bytes.get_bytes(int(func.start_ea), size) or b''
    text = ' '.join(idc.generate_disasm_line(int(ea), 0) or '' for ea in idautils.FuncItems(int(func.start_ea))).lower()
    unload = (
        b'\xff\x15' in raw
        or 'freelibrary' in text
        or 'dlclose' in text
        or any(call_is_unload_import(int(ea)) for ea in idautils.FuncItems(int(func.start_ea)))
    )
    deref = any(marker in raw for marker in DEREF_MARKERS) or 'dword ptr [' in text
    return unload and deref

def scan_function(func):
    hits = []
    rejected = []
    for ea in idautils.FuncItems(int(func.start_ea)):
        if insn_mnem(ea) != 'call':
            continue
        prev = previous_head(ea, func)
        pushed = False if prev is None else pushes_global(prev)
        for target in call_targets(ea):
            callee = ida_funcs.get_func(int(target))
            if callee is None or int(callee.start_ea) != int(target):
                continue
            shaped = function_derefs_arg0_and_unloads(callee)
            rec = {
                'call': hex(int(ea)),
                'prev': None if prev is None else hex(int(prev)),
                'pushed_global': pushed,
                'target': hex(int(target)),
                'size': hex(int(callee.end_ea) - int(target)),
                'shaped': shaped,
                'disasm': idc.generate_disasm_line(int(ea), 0) or '',
            }
            if pushed and shaped:
                hits.append(int(target))
            elif int(callee.end_ea) - int(target) <= 0x30:
                rejected.append(rec)
    return hits, rejected

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(CLIENTDLL_INIT_EA))
    if owner is None or int(owner.start_ea) != int(CLIENTDLL_INIT_EA):
        raise RuntimeError('ClientDLL_Init is not a function start')
    scan_starts = {int(owner.start_ea)}
    for ea in idautils.FuncItems(int(owner.start_ea)):
        if insn_mnem(ea) == 'call':
            scan_starts.update(call_targets(ea))
    found = []
    scanned = []
    rejected = []
    for start in sorted(scan_starts):
        func = ida_funcs.get_func(int(start))
        if func is None or int(func.start_ea) != int(start):
            continue
        scanned.append({'ea': hex(start), 'name': idc.get_func_name(start) or '', 'size': hex(int(func.end_ea) - start)})
        hits, local_rejected = scan_function(func)
        found.extend(hits)
        rejected.extend(local_rejected)
    unique = sorted(set(found))
    named = ida_name.get_name_ea(idaapi.BADADDR, 'FreeBlob')
    if len(unique) != 1 and named != idaapi.BADADDR and int(named) in scan_starts:
        named_func = ida_funcs.get_func(int(named))
        if named_func is not None and int(named_func.start_ea) == int(named):
            unique = [int(named)]
    if len(unique) != 1:
        result = json.dumps({
            'error': 'FreeBlob is not unique from ClientDLL_Init unload paths',
            'owner': hex(int(owner.start_ea)),
            'candidates': [hex(ea) for ea in unique],
            'rejected': rejected[:20],
            'scanned': scanned,
        })
    else:
        start = unique[0]
        try:
            ida_name.set_name(start, 'FreeBlob', ida_name.SN_FORCE)
        except Exception:
            pass
        func = ida_funcs.get_func(start)
        result = json.dumps({
            'pointer_size': 4,
            'func_ea': hex(start),
            'func_size': hex(int(func.end_ea) - start) if func else None,
            'owner': hex(int(owner.start_ea)),
            'scanned_count': len(scanned),
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


async def _locate_freeblob(session, clientdll_init_ea):
    code = LOCATE_PY.replace("CLIENTDLL_INIT_EA_PLACEHOLDER", str(int(clientdll_init_ea)))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    return payload


async def _inspect_target(session, func_ea, image_base, *, allow_across):
    function = await _inspect_function_via_mcp(
        session,
        func_ea,
        image_base,
        TARGET_FUNCTION_NAME,
        allow_across_function_boundary=allow_across,
    )
    if function and function.get("func_sig"):
        return function, allow_across
    if not allow_across:
        function = await _inspect_function_via_mcp(
            session,
            func_ea,
            image_base,
            TARGET_FUNCTION_NAME,
            allow_across_function_boundary=True,
        )
        if function and function.get("func_sig"):
            return function, True
    return None, False


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    _ = skill_name, old_yaml_map, llm_config
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNCTION_NAME)
    if output is None:
        return False
    owner = _function_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner is None:
        if debug:
            print("  find-FreeBlob: missing ClientDLL_Init artifact")
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
            print("  find-FreeBlob: failed to verify ClientDLL_Init artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_freeblob(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-FreeBlob: locator failed {located}")
        return False
    try:
        func_ea = int(located["func_ea"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    if func_ea < int(image_base):
        return False
    function, allow_across = await _inspect_target(session, func_ea, image_base, allow_across=False)
    if function is None:
        if debug:
            print(f"  find-FreeBlob: function inspect failed ea={located.get('func_ea')}")
        return False
    try:
        inspected_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_va != func_ea:
        return False
    if debug:
        print(f"  find-FreeBlob: ea={located['func_ea']} size={located.get('func_size')} across={allow_across}")
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
