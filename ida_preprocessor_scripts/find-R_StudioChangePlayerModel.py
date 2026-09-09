#!/usr/bin/env python3
"""Locate R_StudioChangePlayerModel (Windows builds of every family).

studioapi_SetupPlayerModel (consumed from its verified artifact) calls the
engine's per-entity player-model reset routine R_StudioChangePlayerModel()
( void ) with no arguments from its model-change paths — MSVC merges the
two source call sites into one on hl-4554..hl-10210 and cof-5936, keeps
both on the WON-era builds and SvEngine. The locator walks the direct
E8 call sites whose callee takes no stack arguments and accepts the unique
callee that (1) references the same writable-data global studioapi_Setup-
PlayerModel dereferences at +0x0B94 (currententity->model), (2) contains
the MAX_SKINS == 11 immediate, and (3) stores 0xFFFFFFFF (topcolor /
bottomcolor reset). Host_IsSinglePlayerGame is also a 0-arg callee but
references none of that; Q_strncpy carries three arguments.

Linux builds inline the routine into studioapi_SetupPlayerModel (no direct
call survives), so this finder is Windows-only by design.

Direct-locator rationale: validated on hl-3248..hl-10210, cof-5936, and
svencoop-10257 Windows images. Discovery never uses a byte signature or an
old artifact signature.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNC_NAME = "R_StudioChangePlayerModel"
OWNER_FUNC_NAME = "studioapi_SetupPlayerModel"
CURRENTENTITY_MODEL_OFFSET = 0x0B94

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

SETUP_EA = SETUP_EA_PLACEHOLDER
CURRENTENTITY_MODEL_OFFSET = 0xB94

def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return bool(perms & writable) and not bool(perms & executable)

def disasm(ea):
    return idc.generate_disasm_line(int(ea), 0) or ''

def func_items(start):
    fn = ida_funcs.get_func(int(start))
    if fn is None:
        return []
    return [ea for ea in idautils.FuncItems(int(fn.start_ea))]

def reg_name(op):
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None

def writable_dword_operands(ea):
    # Structured operand extraction only: a raw byte-window scan matches
    # opcode bytes of instructions like `mov eax, [esi+208h]` and decodes
    # them into a mapped .data address, misattributing them as globals.
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return []
    out = []
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            break
        value = None
        if op_type == int(idaapi.o_mem):
            value = int(op.addr) & 0xFFFFFFFF
        elif op_type == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
        elif op_type == int(idaapi.o_displ):
            value = int(op.addr) & 0xFFFFFFFF
        if value is not None and is_writable_data(value):
            out.append((0, value))
    return out

def base_registers_at(items, offset):
    bases = set()
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                try:
                    addr = int(op.addr) & 0xFFFFFFFF
                except Exception:
                    continue
                if addr == offset:
                    name = reg_name(op)
                    if name:
                        bases.add(name)
    return sorted(bases)

def dest_reg32(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or not insn.ops:
        return None
    op = insn.ops[0]
    if int(op.type) != int(idaapi.o_reg):
        return None
    dtype_size = {0: 1, 1: 2, 2: 4, 3: 4, 4: 8, 5: 16}.get(int(getattr(op, 'dtype', 0)), 0)
    if dtype_size != 4:
        return None
    return reg_name(op)

def plain_memory_operand_values(ea):
    # currententity is loaded as `mov reg, [absolute]` (o_mem). Composed
    # array reads like `mov eax, dword_X[edi]` (o_displ with an index) reuse
    # the same destination register and must not contribute candidates.
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return []
    out = []
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            break
        if op_type == int(idaapi.o_mem):
            value = int(op.addr) & 0xFFFFFFFF
            if is_writable_data(value):
                out.append(value)
    return out


def find_currententity_global(items):
    bases = set(base_registers_at(items, CURRENTENTITY_MODEL_OFFSET))
    if not bases:
        return None
    found = set()
    for ea in items:
        dest = dest_reg32(ea)
        if dest is None or dest not in bases:
            continue
        for value in plain_memory_operand_values(ea):
            found.add(value)
    if len(found) != 1:
        return None
    return next(iter(found))

def direct_call_sites(items):
    sites = []
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size < 5:
            continue
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        if not raw or raw[0] != 0xE8:
            continue
        rel = int.from_bytes(raw[1:5], 'little', signed=True)
        target = (ea + 5 + rel) & 0xFFFFFFFF
        sites.append((int(ea), int(insn.size), target))
    return sites

def zero_arg_site(items, index, sites):
    # A cdecl call with arguments is followed by `add esp, N` (N > 0).
    # Epilogue pops and stack-frame pushes are not argument cleanup, so a
    # push-window scan would only misfire on prologues; the semantic
    # filters below carry the actual discrimination.
    _ = items, index
    ea, insn_len, _target = sites[index]
    following = ea + insn_len
    finsn = idautils.DecodeInstruction(following)
    if finsn and finsn.size >= 3:
        raw = ida_bytes.get_bytes(following, finsn.size) or b''
        if raw and raw[0] == 0x83 and (raw[1] & 0xF8) == 0xC4 and raw[2] != 0:
            return False
    return True

def body_text(func_ea):
    lines = []
    for ea in func_items(func_ea):
        lines.append(disasm(ea))
    return ' '.join(lines)

def main():
    fn = ida_funcs.get_func(SETUP_EA)
    if fn is None or int(fn.start_ea) != SETUP_EA:
        return {'error': 'studioapi_SetupPlayerModel is not a function start'}
    items = func_items(SETUP_EA)
    currententity = find_currententity_global(items)
    if currententity is None:
        return {'error': 'currententity global not uniquely identified in studioapi_SetupPlayerModel'}
    sites = direct_call_sites(items)
    callees = {}
    site_counts = {}
    for index, (ea, insn_len, target) in enumerate(sites):
        callee_fn = ida_funcs.get_func(target)
        if callee_fn is None or int(callee_fn.start_ea) != target:
            continue
        if not zero_arg_site(items, index, sites):
            continue
        if target in callees:
            site_counts[target] += 1
            continue
        text = body_text(target)
        refs_entity = False
        for c_ea in func_items(target):
            for value in plain_memory_operand_values(c_ea):
                if value == currententity:
                    refs_entity = True
                    break
            if refs_entity:
                break
        if not refs_entity:
            continue
        if '0Bh' not in text or '0FFFFFFFFh' not in text:
            continue
        callees[target] = {
            'call_site': hex(ea),
            'call_insn_len': insn_len,
            'refs_currententity': hex(currententity),
        }
        site_counts[target] = 1
    if len(callees) != 1:
        return {'error': 'R_StudioChangePlayerModel callee candidates: %d' % len(callees),
                'currententity': hex(currententity),
                'callees': [hex(t) for t in sorted(callees)]}
    target, info = next(iter(callees.items()))
    cfn = ida_funcs.get_func(target)
    return {
        'pointer_size': 4,
        'setup_va': hex(SETUP_EA),
        'currententity': hex(currententity),
        'func_va': hex(target),
        'func_end': hex(int(cfn.end_ea)),
        'call_sites': site_counts[target],
        'first_call_site': info['call_site'],
    }

globals().update(locals())
try:
    if idaapi.inf_is_64bit():
        result = json.dumps({'error': 'expected 32-bit x86'})
    else:
        result = json.dumps(main())
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _owner_artifact(new_binary_dir, platform, func_name, image_base):
    path = Path(new_binary_dir) / f"{func_name}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
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


async def _locate_rscpm(session, setup_ea):
    try:
        code = LOCATE_PY.replace("SETUP_EA_PLACEHOLDER", str(int(setup_ea)))
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    if "func_va" not in payload:
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
    if platform != "windows":
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    if output is None:
        return False
    owner = _owner_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner is None:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: missing {OWNER_FUNC_NAME} artifact")
        return False
    owner_data, setup_ea = owner
    located = await _locate_rscpm(session, setup_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: locator failed {located}")
        return False
    try:
        func_ea = int(located["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(
        session,
        func_ea,
        image_base,
        TARGET_FUNC_NAME,
        allow_across_function_boundary=bool(owner_data.get("func_sig_allow_across_function_boundary")),
    )
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: failed to inspect {located['func_va']}")
        return False
    try:
        inspected_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_va != func_ea:
        return False
    if debug:
        print(
            f"  find-{TARGET_FUNC_NAME}: func={located['func_va']} "
            f"currententity={located.get('currententity')} "
            f"call_sites={located.get('call_sites')}"
        )
    write_func_yaml(
        output,
        {
            "func_name": TARGET_FUNC_NAME,
            "func_va": function["func_va"],
            "func_rva": function["func_rva"],
            "func_size": function["func_size"],
            "func_sig": function["func_sig"],
        },
    )
    return True
