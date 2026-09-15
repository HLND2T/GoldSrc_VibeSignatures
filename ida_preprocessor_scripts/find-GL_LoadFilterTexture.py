#!/usr/bin/env python3
"""Locate GL_LoadFilterTexture through its 8x8 filter-texture constants.

GL_LoadFilterTexture (engine/gl_draw.c) allocates an 8*8*3 (0xC0) byte RGB
(0x1907) buffer and uploads it through the GL filter texture. It owns no
diagnostic string, so the deterministic locator is the pair of body constants
0xC0 and 0x1907: the function whose body uses both as instruction immediates
is unique on every validated Windows and Linux engine build (SvEngine keeps
the same constants while restructuring the GL_Bind call out of the body;
Linux inlines GL_Bind entirely). A byte-level prefilter narrows the scan,
then every candidate is verified instruction-by-instruction so the constants
must come from o_imm operands, never from displacements or unrelated data.
The optional GL_Bind artifact (declared as optional_input in the configs)
adds a direct-callee discriminator when present.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNCTION_NAME = "GL_LoadFilterTexture"
MIN_FUNCTION_SIZE = 0x40
MAX_FUNCTION_SIZE = 0x600

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_nalt
import idaapi
import idautils
import idc
import json
import traceback

MIN_FUNCTION_SIZE = MIN_FUNCTION_SIZE_PLACEHOLDER
MAX_FUNCTION_SIZE = MAX_FUNCTION_SIZE_PLACEHOLDER
GLBIND_EA = GLBIND_EA_PLACEHOLDER

ALLOC_FREE_NAMES = ('free', '_ZdlPv', '_ZdaPv', 'malloc')


def call_target_is_alloc_free(ea):
    import ida_name
    for xref in idautils.XrefsFrom(int(ea), 0):
        name = ida_name.get_name(int(xref.to)) or ''
        if name.lstrip('_') in ALLOC_FREE_NAMES or name in ALLOC_FREE_NAMES:
            return True
        line = idc.generate_disasm_line(int(ea), 0) or ''
        if any(free_name in line for free_name in ALLOC_FREE_NAMES):
            return True
    return False


def function_calls_alloc_free(start):
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if insn is None:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        if mnem not in ('call', 'jmp'):
            continue
        if call_target_is_alloc_free(ea):
            return True
    return False


def function_calls_glbind(start):
    if not GLBIND_EA:
        return False
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if insn is None:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        if mnem not in ('call', 'jmp'):
            continue
        for xref in idautils.XrefsFrom(int(ea), 0):
            if int(xref.to) == int(GLBIND_EA):
                return True
    return False


def function_imm_constants(start):
    # Immediate-operand values only: addresses of globals and branch targets
    # are o_mem/o_displ/o_near operands and must never satisfy the constant
    # pair, so a synthetic function whose bytes merely contain the sequences
    # (e.g. a displacement or an unrelated 32-bit word) is rejected here.
    values = set()
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_imm):
                values.add(int(op.value) & 0xFFFFFFFF)
                values.add(int(op.value) & 0xFFFF)
    return values


def collect_constant_pair_functions():
    found = []
    for start in idautils.Functions():
        func = ida_funcs.get_func(int(start))
        if func is None or int(func.start_ea) != int(start):
            continue
        size = int(func.end_ea) - int(start)
        if size < int(MIN_FUNCTION_SIZE) or size > int(MAX_FUNCTION_SIZE):
            continue
        body = ida_bytes.get_bytes(int(start), size) or b''
        if b'\xC0\x00\x00\x00' not in body:
            continue
        if b'\x07\x19\x00\x00' not in body:
            continue
        immediates = function_imm_constants(start)
        if 0xC0 not in immediates or 0x1907 not in immediates:
            continue
        found.append({
            'ea': hex(int(start)),
            'size': hex(size),
            'name': idc.get_func_name(int(start)) or '',
        })
    return found


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    constant_matches = collect_constant_pair_functions()
    by_ea = {}
    for record in constant_matches:
        by_ea[record['ea']] = record
    # Waterfall of deterministic discriminators, strongest first: a direct
    # GL_Bind call (Windows hl/cof families), an allocator call through a
    # named import (SvEngine Windows, Linux), then the bare constant pair
    # (only accepted when unique on its own).
    stages = []
    if GLBIND_EA:
        stages.append(('glbind', lambda rec: function_calls_glbind(int(rec['ea'], 0))))
    stages.append(('allocfree', lambda rec: function_calls_alloc_free(int(rec['ea'], 0))))
    stages.append(('constants', lambda rec: True))
    matches = None
    stage_used = None
    for stage_name, predicate in stages:
        selected = [rec for rec in constant_matches if predicate(rec)]
        if len(selected) == 1:
            matches = selected
            stage_used = stage_name
            break
        if stage_name != 'constants' and len(selected) > 1:
            continue
    if matches is None or len(matches) != 1:
        result = json.dumps({
            'error': 'GL_LoadFilterTexture constant pair is not unique',
            'matches': constant_matches,
        })
    else:
        record = matches[0]
        start = int(record['ea'], 0)
        try:
            import ida_name
            ida_name.set_name(start, 'GL_LoadFilterTexture', ida_name.SN_FORCE)
        except Exception:
            pass
        result = json.dumps({
            'pointer_size': 4,
            'func_ea': record['ea'],
            'func_size': record['size'],
            'stage': stage_used,
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


GLBIND_FUNC_NAME = "GL_Bind"


def _glbind_ea(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{GLBIND_FUNC_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != GLBIND_FUNC_NAME:
        return 0
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return 0
    if func_ea < int(image_base):
        return 0
    return func_ea


async def _locate_filter_texture(session, glbind_ea):
    code = (
        LOCATE_PY.replace("MIN_FUNCTION_SIZE_PLACEHOLDER", str(MIN_FUNCTION_SIZE))
        .replace("MAX_FUNCTION_SIZE_PLACEHOLDER", str(MAX_FUNCTION_SIZE))
        .replace("GLBIND_EA_PLACEHOLDER", str(int(glbind_ea or 0)))
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
    located = await _locate_filter_texture(session, _glbind_ea(new_binary_dir, platform, image_base))
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-GL_LoadFilterTexture: locator failed {located}")
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
            print(f"  find-GL_LoadFilterTexture: function inspect failed ea={located.get('func_ea')}")
        return False
    try:
        inspected_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_va != func_ea:
        return False
    if debug:
        print(
            f"  find-GL_LoadFilterTexture: ea={function['func_va']} size={function.get('func_size')} across={allow_across}"
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
