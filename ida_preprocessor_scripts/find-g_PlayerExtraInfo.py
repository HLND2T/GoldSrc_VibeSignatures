#!/usr/bin/env python3
"""Recover the real player-extra array from Debug_ShowPlayerData's row loop.

The owned printf format identifies the debug routine on all four targets.
Its first row is player 1; frags/deaths/team/health/armor accesses and the
row advance independently identify the array, without an LLM field guess.
8948 ELF names the underlying storage g_PlayerExtraInfo. The real array
includes row 0: Windows 10257's 0x10644974 is row 1, not its symbol base.
The verified stride is 88 in 8948 and 92 in 10257. Never copy that layout
between builds. Direct recovery is preferable to LLM here because the same
loop provides both the selected address operand and its row adjustment.
GCC 8948 loads a GOT pointer then adds one stride; GCC 10257 uses GOTOFF
LEA for row 1; MSVC materializes row 1 as an immediate. Shared GV metadata
encodes the validated adjustment/PIC addend for runtime resolution.
"""

from ida_analyze_util import _inspect_function_via_mcp, parse_mcp_result
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._sven_client_pic_common import unique_string_owner_ea

TARGET_GLOBAL_NAMES = ["g_PlayerExtraInfo"]
LITERAL = "%d %s %d %s %.2f %.2f %d %.2f %d %s\n"

WALK = r"""
def locate(owner):
    import idaapi, ida_bytes, ida_funcs, ida_segment, ida_ua, idautils, idc
    if idaapi.inf_is_64bit():
        return None
    items = list(idautils.FuncItems(owner))
    got = None
    got_reg = None
    for i, ea in enumerate(items[:12]):
        if idc.print_insn_mnem(ea) == 'call' and i + 1 < len(items):
            nxt = items[i + 1]
            if idc.print_insn_mnem(nxt) == 'add' and idc.get_operand_type(nxt, 1) == idaapi.o_imm:
                thunk = ida_funcs.get_func(idc.get_operand_value(ea, 0))
                if thunk and thunk.end_ea - thunk.start_ea <= 4:
                    got = (nxt + idc.get_operand_value(nxt, 1)) & 0xffffffff
                    got_reg = idc.print_operand(nxt, 0)
                    break
    candidates = []
    regs = {}
    advances = []
    counters = set()
    bounds = []
    for ea in items:
        ins = ida_ua.insn_t()
        if not ida_ua.decode_insn(ins, ea):
            return None
        m = idc.print_insn_mnem(ea)
        dst = idc.print_operand(ea, 0)
        if m == 'mov' and ins.ops[0].type == idaapi.o_reg and ins.ops[1].type == idaapi.o_imm:
            if int(ins.ops[1].value) == 1:
                counters.add(dst)
        if m == 'cmp' and ins.ops[0].type == idaapi.o_reg and ins.ops[1].type == idaapi.o_imm:
            bounds.append((dst, int(ins.ops[1].value)))
        # Record field reads while the initial row pointer is live.
        for op in ins.ops:
            if op.type not in (idaapi.o_phrase, idaapi.o_displ):
                continue
            text = idc.print_operand(ea, op.n)
            for reg, candidate in regs.items():
                if text.strip().endswith('[' + reg + ']'):
                    candidate['fields'].add(0)
                elif '[' + reg + '+' in text and int(op.addr) in (4, 10, 76, 80):
                    candidate['fields'].add(int(op.addr))
        if m == 'add' and ins.ops[0].type == idaapi.o_reg and ins.ops[1].type == idaapi.o_imm:
            if int(ins.ops[1].value) in (88, 92):
                advances.append((dst, int(ins.ops[1].value)))
        if m == 'lea' and ins.ops[1].type == idaapi.o_displ and int(ins.ops[1].addr) in (88, 92):
            text = idc.print_operand(ea, 1)
            for reg in regs:
                if '[' + reg + '+' in text:
                    advances.append((reg, int(ins.ops[1].addr)))
        if m not in ('mov', 'lea') or ins.ops[0].type != idaapi.o_reg:
            continue
        source = ins.ops[1]
        value = None
        reference = None
        if m == 'mov' and source.type == idaapi.o_imm:
            value = int(source.value)
            reference = (ea, ins.size, source.offb)
        elif source.type == idaapi.o_displ:
            text = idc.print_operand(ea, 1)
            if got is not None and '[' + got_reg in text:
                address = (got + int(source.addr)) & 0xffffffff
                if ida_segment.getseg(address):
                    value = address if m == 'lea' else ida_bytes.get_dword(address)
                    reference = (ea, ins.size, source.offb)
            elif m == 'lea':
                for reg, previous in regs.items():
                    if '[' + reg + '+' in text and int(source.addr) in (88, 92):
                        value = previous['value'] + int(source.addr)
                        reference = previous['reference']
                        break
        regs.pop(dst, None)
        segment = ida_segment.getseg(value) if value is not None else None
        if reference and segment and segment.perm & 2:
            candidate = {'reg': dst, 'value': value, 'reference': reference, 'fields': set()}
            candidates.append(candidate)
            regs[dst] = candidate
    selected = []
    for candidate in candidates:
        strides = {stride for reg, stride in advances if reg == candidate['reg']}
        if not {0, 4, 10, 76, 80}.issubset(candidate['fields']) or len(strides) != 1:
            continue
        stride = strides.pop()
        base = candidate['value'] - stride
        if not counters or not any(
            (reg == candidate['reg'] and value == base + stride * 32)
            or (reg in counters and value == 33)
            for reg, value in bounds
        ):
            continue
        segment = ida_segment.getseg(base)
        if not segment or not segment.perm & 2 or base + stride * 33 > segment.end_ea:
            continue
        # ELF's real symbol is an independent check when present.
        named = idc.get_name_ea_simple('g_PlayerExtraInfo')
        if named != idaapi.BADADDR and named != base:
            continue
        ea, length, disp = candidate['reference']
        if not disp or disp + 4 > length:
            continue
        selected.append({'gv_ea': base, 'insn_ea': ea, 'insn_len': length,
                         'insn_disp': disp, 'stride': stride})
    return selected[0] if len(selected) == 1 else None
import json
result = json.dumps(locate(OWNER))
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    owner_ea = await unique_string_owner_ea(session, LITERAL, "Debug_ShowPlayerData", debug)
    if owner_ea is None:
        return False
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": WALK.replace("OWNER", str(owner_ea))}))
    if not isinstance(located, dict):
        if debug:
            print("  g_PlayerExtraInfo: row-loop evidence is absent or ambiguous")
        return False
    function = await _inspect_function_via_mcp(session, owner_ea, image_base, "Debug_ShowPlayerData")
    if not function:
        return False
    if debug:
        print(f"  g_PlayerExtraInfo: {located}")
    owner = {
        "owner_ea": owner_ea,
        "owner_end": owner_ea + int(function["func_size"], 0),
        "function": function,
        "allow_across": False,
    }
    return await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {TARGET_GLOBAL_NAMES[0]: located}
    )
