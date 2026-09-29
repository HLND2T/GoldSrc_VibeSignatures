"""IDA-side helpers for CS-family VGUI finders and cross-module Panel::Init.

The locator bodies run inside the owned worker's ``py_eval`` through ``run_walk``
so only candidate addresses and verdicts cross MCP. Host-side callers stay thin.
"""

import json

from ida_analyze_util import _inspect_function_via_mcp, parse_mcp_result
from ida_elf import ELF_RESOLVER_PY

# KeyValues::LoadFromFile occupies slot 2 of the KeyValues primary vtable on every
# verified build (MSVC ??_7KeyValues@@6B@ and Itanium _ZTV9KeyValues+8 alike).
LOADFROMFILE_SLOT_INDEX = 2

# Unicode byte-order-mark sentinel from CTeamMenu::LoadMapPage
# (vgui2/game_controls/teammenu.cpp: `memBlock[0] != 0xFEFF`).
RICHTEXT_BOM = 0xFEFF

# CTeamMenu's base vgui2::Panel::Init writes its member defaults through this
# offset sequence on both compiler families: byte stores for _pinCorner(+0x30)
# / _autoResize(+0x28) / _drawBorder(+0x4a), dword zeroing of the cursor and
# paint bounds (+0x60/+0x5c), and _proportional (+0x24) set to 2.
PANEL_INIT_STORE_OFFSETS = (0x30, 0x28, 0x4A, 0x60, 0x5C, 0x24)

FRAME_CLASS = "vgui2::Frame"
FRAME_VTABLE_ALIASES = {
    "windows": ["??_7Frame@vgui2@@6B@"],
    "linux": ["_ZTVN5vgui25FrameE"],
}

DECODER = (
    ELF_RESOLVER_PY
    + r"""
import ida_bytes, ida_funcs, ida_nalt, ida_segment, ida_ua, idaapi, idautils, idc, json


def imm_value(operand):
    # IDA sign-extends narrow immediates into a 64-bit value; the low 16 bits
    # carry a word-sized encoding such as the 0xFEFF BOM compare.
    if int(operand.dtype) in (0, 1):
        return int(operand.value) & 0xFFFF
    return int(operand.value) & 0xFFFFFFFF


def mapped(ea):
    return 0 <= int(ea) <= 0xFFFFFFFF and ida_segment.getseg(int(ea)) is not None


def executable_target(ea):
    if not mapped(ea):
        return False
    segment = ida_segment.getseg(int(ea))
    function = ida_funcs.get_func(int(ea))
    return (segment is not None and segment.perm & ida_segment.SEGPERM_EXEC
            and function is not None and int(function.start_ea) == int(ea))


def exact_string_eas(literal):
    eas = []
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    for item in strings:
        if str(item) == literal:
            eas.append(int(item.ea))
    return eas


def string_owner_evidence(literal):
    eas = exact_string_eas(literal)
    evidence = {'count': len(eas), 'ea': [hex(ea) for ea in eas], 'ref_sites': [], 'owners': []}
    if len(eas) != 1:
        return evidence
    owners = set()
    for ref in idautils.XrefsTo(eas[0], 0):
        if not ida_bytes.is_code(ida_bytes.get_flags(ref.frm)):
            continue
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.add(int(function.start_ea))
            evidence['ref_sites'].append(int(ref.frm))
    evidence['ref_sites'] = sorted(set(evidence['ref_sites']))
    evidence['owners'] = sorted(owners)
    return evidence


def require_single_owner(evidence, literal):
    if evidence.get('count') != 1 or len(set(evidence.get('owners') or [])) != 1:
        raise ValueError('anchor owner is not unique for ' + literal + ': ' + json.dumps(evidence))
    return int(evidence['owners'][0])


def function_body(ea):
    function = ida_funcs.get_func(int(ea))
    if function is None:
        return []
    return list(idautils.FuncItems(int(function.start_ea)))


def direct_call_target(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if insn is None or insn.get_canon_mnem() != 'call':
        return None
    operand = insn.ops[0]
    if operand.type in (idaapi.o_near, idaapi.o_far):
        return resolve_elf_plt(int(operand.addr))
    return None


def first_direct_call_after(site, limit=0x60):
    cursor = int(site)
    end = cursor + int(limit)
    while cursor < end:
        target = direct_call_target(cursor)
        if target is not None:
            return target
        insn = idautils.DecodeInstruction(cursor)
        if insn is None:
            return None
        cursor += insn.size
    return None


def first_direct_call_targets(sites, limit=0x60):
    targets = []
    for site in sites:
        target = first_direct_call_after(site, limit)
        if target is not None:
            targets.append(target)
    return targets


def valid_vtable_slots(table, minimum=4, maximum=128):
    slots = []
    if not mapped(table):
        return slots
    for index in range(maximum):
        target = int(ida_bytes.get_dword(int(table) + index * 4))
        if not executable_target(target):
            break
        slots.append(target)
    return slots if len(slots) >= minimum else []
"""
)


async def run_walk(session, body, values=None):
    """Execute a locator body inside the worker and return its JSON result."""
    source = DECODER + "\n" + body
    wrapper = (
        'def main():\n import traceback, json\n ns = {"values": ' + repr(values or {}) + "}\n"
        " try:\n  exec(" + json.dumps(source) + ',ns)\n  return json.dumps(ns["result"])\n'
        ' except Exception:\n  return json.dumps({"error": traceback.format_exc()[-1500:]})\nresult = main()'
    )
    payload = parse_mcp_result(await session.call_tool("py_eval", {"code": wrapper}))
    if not isinstance(payload, dict):
        return {"error": f"unexpected walk payload: {payload!r}"}
    return payload


async def inspect_unique_function(session, name, target, image_base, debug=False):
    """Inspect one already located function and require a unique x86 signature."""
    function = await _inspect_function_via_mcp(session, target, image_base, name)
    allow_across = function is None or not function.get("func_sig")
    if allow_across:
        function = await _inspect_function_via_mcp(
            session, target, image_base, name, allow_across_function_boundary=True
        )
        if function is not None:
            function["func_sig_allow_across_function_boundary"] = True
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {name}: no unique signature at {hex(target)}")
        return None
    return function
