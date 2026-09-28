#!/usr/bin/env python3
"""Recover the CS client VGUI helpers through CTeamMenu's two invariant literals.

``CTeamMenu::CTeamMenu`` loads ``Resource/UI/TeamMenu.res`` through
``vgui2::Frame::LoadControlSettings``; the literal occurs once per verified build.
The first direct call after the literal site that consumes it as its resource-name
argument is the LoadControlSettings entry — the thiscall ``push imm32`` form on
MSVC and the cdecl ``mov [esp+4], reg`` store on GCC (whose earlier calls belong
to the team-button CUtlVector and must be skipped).

``CTeamMenu::LoadMapPage`` owns the single ``maps/%s.txt`` format string, so that
literal's unique code reference already identifies the function entry — the same
owner MetaHookSv reached by disassembling forward from the string push. The body's
byte-order-mark check ``memBlock[0] != 0xFEFF`` (vgui2/game_controls/teammenu.cpp)
branches between ``RichText::SetText(const char*)`` on fall-through and
``RichText::SetText(const wchar_t*)`` at the conditional-branch target. Locating
the branch target's first direct call — instead of MetaHookSv's "next two calls"
window — avoids picking up the trailing ``GotoTextStart`` call.
"""

from ida_analyze_util import (
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import (
    FRAME_CLASS,
    FRAME_VTABLE_ALIASES,
    RICHTEXT_BOM,
    inspect_unique_function,
    run_walk,
)

LOADCS_SYMBOL = "ClientVGUI_LoadControlSettings"
SETTEXTA_SYMBOL = "ClientVGUI_RichText_SetTextA"
SETTEXTW_SYMBOL = "ClientVGUI_RichText_SetTextW"
LOADMAP_SYMBOL = "TeamMenu_LoadMapPage"
FRAME_ACTIVATE_SYMBOL = "ClientVGUI_Frame_Activate"
TEAMMENU_LITERAL = "Resource/UI/TeamMenu.res"
MAPS_LITERAL = "maps/%s.txt"
FRAME_ACTIVATE_NAME = "vgui2::Frame::Activate()"
# Source: Frame::Activate calls MoveToFront, RequestFocus, SetVisible(true),
# SetEnabled(true), then surface()->SetMinimized(..., false). The Panel and
# surface interface slots differ by one entry between the MSVC and GCC ABIs.
# GCC loads SetMinimized into a register before calling it, so only the four
# Panel dispatches appear as indirect memory-call operands on that platform.
FRAME_ACTIVATE_DISPATCHES = {
    "windows": (0xC8, 0x30, 0x74, 0xBC),
    "linux": (0xCC, 0x30, 0x78, 0xC0),
}
FRAME_SET_MINIMIZED_DISPATCH = {"windows": 0x94, "linux": 0x98}

# Walk forward from the TeamMenu.res immediate site to the direct call whose
# arguments carry that string: MSVC pushes it as thiscall arg #1 right before the
# call, GCC stores the loaded register into the first cdecl stack slot. The
# register is tracked from the immediate load so unrelated earlier calls
# (team-button vector construction) are not consumed by mistake.
WALK = r"""
def anchor_register(site):
    insn = idautils.DecodeInstruction(site)
    if insn is None:
        return None, None
    mnemonic = idautils.DecodeInstruction(site).get_canon_mnem()
    if mnemonic == 'push' and insn.ops[0].type == ida_ua.o_imm:
        return 'stack', None
    if mnemonic == 'mov' and insn.ops[0].type == ida_ua.o_reg:
        return 'reg', idc.print_operand(site, 0).lower()
    return None, None


def register_stored_to_arg1(ea, register):
    insn = idautils.DecodeInstruction(ea)
    if insn is None or idautils.DecodeInstruction(ea).get_canon_mnem() != 'mov':
        return False
    dest_text = idc.print_operand(ea, 0).lower()
    source_text = idc.print_operand(ea, 1).lower()
    return (source_text == register and insn.ops[0].type in (ida_ua.o_displ, ida_ua.o_phrase)
            and int(insn.ops[0].addr) in (0, 4) and ('esp' in dest_text or 'ebp' in dest_text))


def find_load_control_settings(site):
    # MSVC pushes the literal as thiscall arg #1 immediately before the call.
    # GCC keeps it in a register across an unrelated vector-construction call
    # and stores it into the first cdecl argument slot ([esp+4]) right before
    # the LoadControlSettings call. Track the register through intermediate
    # calls: a register reloaded from [esp+arg] stays live, other sources end
    # the walk.
    kind, register = anchor_register(site)
    if kind is None:
        return None
    cursor = int(site)
    first = True
    for _ in range(64):
        insn = idautils.DecodeInstruction(cursor)
        if insn is None or insn.get_canon_mnem().startswith('ret'):
            return None
        if not first and kind == 'reg' and register_clobbered(cursor, register):
            return None
        first = False
        if kind == 'reg' and register_stored_to_arg1(cursor, register):
            # The next direct call consumes the slot that now holds the literal.
            return first_direct_call_after(cursor, 0x10)
        if kind == 'stack':
            target = direct_call_target(cursor)
            if target is not None:
                return target
        cursor += insn.size
    return None


def register_clobbered(ea, register):
    insn = idautils.DecodeInstruction(ea)
    if insn is None or len(insn.ops) < 1:
        return False
    mnemonic = insn.get_canon_mnem()
    if mnemonic == 'mov' and insn.ops[0].type == ida_ua.o_reg:
        return idc.print_operand(ea, 0).lower() == register
    if mnemonic == 'pop':
        return idc.print_operand(ea, 0).lower() == register
    return False


def bom_branch_settexts(owner, bom):
    cmp_sites = []
    for ea in function_body(owner):
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            continue
        mnemonic = idautils.DecodeInstruction(ea).get_canon_mnem()
        if mnemonic == 'cmp' and insn.ops[1].type == ida_ua.o_imm and imm_value(insn.ops[1]) == bom:
            cmp_sites.append(ea)
        elif (mnemonic == 'mov' and insn.ops[1].type == ida_ua.o_imm
              and imm_value(insn.ops[1]) == bom and insn.ops[0].type == ida_ua.o_reg):
            # 10210-family: mov eax, 0xFEFF ... cmp [mem], ax
            follower = ea + insn.size
            for _ in range(3):
                nxt = idautils.DecodeInstruction(follower)
                if nxt is None:
                    break
                if idautils.DecodeInstruction(follower).get_canon_mnem() == 'cmp':
                    cmp_sites.append(follower)
                    break
                follower += nxt.size
    if len(cmp_sites) != 1:
        raise ValueError('BOM compare is not unique: ' + repr([hex(ea) for ea in cmp_sites]))
    cmp_ea = cmp_sites[0]
    cmp_insn = idautils.DecodeInstruction(cmp_ea)
    branch_target = None
    cursor = cmp_ea + cmp_insn.size
    for _ in range(4):
        insn = idautils.DecodeInstruction(cursor)
        if insn is None:
            break
        mnemonic = insn.get_canon_mnem()
        # IDA renders the 0x74/0x0F84 encoding as either jz or je.
        if mnemonic in ('je', 'jz') and insn.ops[0].type in (ida_ua.o_near, ida_ua.o_far):
            branch_target = int(insn.ops[0].addr)
            break
        if mnemonic.startswith('j') or mnemonic.startswith('ret'):
            break
        cursor += insn.size
    if branch_target is None:
        raise ValueError('no conditional branch after BOM compare at ' + hex(cmp_ea))
    settext_a = first_direct_call_after(cursor, 0x40)
    settext_w = first_direct_call_after(branch_target, 0x40)
    if settext_a is None or settext_w is None:
        raise ValueError('SetText call pair not found around ' + hex(cmp_ea))
    return {'cmp': cmp_ea, 'settext_a': settext_a, 'settext_w': settext_w}


values.update(string_owner_evidence(values['teammenu_literal']))
teammenu_owner = require_single_owner(values, values['teammenu_literal'])
loadcs = find_load_control_settings(values['ref_sites'][0])
if loadcs is None:
    raise ValueError('LoadControlSettings call not found after TeamMenu.res site')

values.update(string_owner_evidence(values['maps_literal']))
loadmap_owner = require_single_owner(values, values['maps_literal'])
branch = bom_branch_settexts(loadmap_owner, values['bom'])
result = {
    'teammenu_owner': teammenu_owner,
    'load_control_settings': loadcs,
    'loadmap_owner': loadmap_owner,
    **{key: int(value) for key, value in branch.items()},
}

assert branch['cmp'] in function_body(loadmap_owner), 'BOM compare left the maps owner'
"""


FRAME_WALK = r"""
def has_set_minimized_dispatch(items, after, displacement):
    tail = [ea for ea in items if ea > after]
    getter_calls = [ea for ea in tail if direct_call_target(ea) is not None]
    if not getter_calls:
        return False
    # The surface getter precedes the final virtual dispatch. GCC may load
    # that slot into a register and call through the register later.
    after_getter = [ea for ea in tail if ea > getter_calls[0]]
    for position, ea in enumerate(after_getter):
        insn = idautils.DecodeInstruction(ea)
        if insn is None:
            continue
        if insn.get_canon_mnem() == 'call':
            operand = insn.ops[0]
            if operand.type == ida_ua.o_displ and int(operand.addr) == displacement:
                return True
        if insn.get_canon_mnem() != 'mov':
            continue
        dest, source = insn.ops[0], insn.ops[1]
        if not (dest.type == ida_ua.o_reg and source.type == ida_ua.o_displ
                and int(source.addr) == displacement):
            continue
        for follower in after_getter[position + 1:]:
            next_insn = idautils.DecodeInstruction(follower)
            if next_insn is None:
                continue
            if (next_insn.get_canon_mnem() == 'call' and next_insn.ops[0].type == ida_ua.o_reg
                    and int(next_insn.ops[0].reg) == int(dest.reg)):
                return True
            if (next_insn.get_canon_mnem() == 'mov' and next_insn.ops[0].type == ida_ua.o_reg
                    and int(next_insn.ops[0].reg) == int(dest.reg)):
                break
    return False


pattern = tuple(values['dispatches'])
matches = []
for index, raw_target in values['entries'].items():
    target = int(raw_target, 0)
    if not executable_target(target):
        continue
    indirect_calls = []
    items = function_body(target)
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if insn is None or insn.get_canon_mnem() != 'call':
            continue
        operand = insn.ops[0]
        if operand.type == ida_ua.o_displ and int(operand.addr) > 0:
            indirect_calls.append((int(operand.addr), int(ea)))
    for start in range(len(indirect_calls) - len(pattern) + 1):
        window = indirect_calls[start:start + len(pattern)]
        if tuple(disp for disp, _ in window) != pattern:
            continue
        if not has_set_minimized_dispatch(items, window[-1][1], values['set_minimized_dispatch']):
            continue
        matches.append((int(index), target))
if len(matches) != 1:
    raise ValueError('Frame::Activate vtable candidate is not unique: ' + repr(matches))
result = {'frame_activate': matches[0][1], 'frame_index': matches[0][0]}
"""


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
    _ = skill_name, old_yaml_map, new_binary_dir
    located = await run_walk(
        session,
        WALK,
        {"teammenu_literal": TEAMMENU_LITERAL, "maps_literal": MAPS_LITERAL, "bom": RICHTEXT_BOM},
    )
    if located.get("error") or "load_control_settings" not in located:
        if debug:
            print(f"  {LOADCS_SYMBOL}: locator failed: {located.get('error', located)}")
        return False
    result = located
    targets = {
        LOADCS_SYMBOL: ("load_control_settings", "vgui2::Frame::LoadControlSettings(char const*, char const*)"),
        SETTEXTA_SYMBOL: ("settext_a", "vgui2::RichText::SetText(char const*)"),
        SETTEXTW_SYMBOL: ("settext_w", "vgui2::RichText::SetText(wchar_t const*)"),
        LOADMAP_SYMBOL: ("loadmap_owner", "CTeamMenu::LoadMapPage(char const*)"),
    }
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in (*targets, FRAME_ACTIVATE_SYMBOL)}
    if not all(outputs.values()):
        return False
    payloads = {}
    for name, (key, function_name) in targets.items():
        function = await inspect_unique_function(session, function_name, result[key], image_base, debug)
        if function is None:
            return False
        payloads[name] = {
            field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")
        }
        if function.get("func_sig_allow_across_function_boundary"):
            payloads[name]["func_sig_allow_across_function_boundary"] = True
    vtable = await preprocess_vtable_via_mcp(
        session,
        FRAME_CLASS,
        image_base,
        platform,
        symbol_aliases=FRAME_VTABLE_ALIASES[platform],
    )
    if vtable is None:
        if debug:
            print(f"  {FRAME_ACTIVATE_SYMBOL}: Frame vtable not found")
        return False
    frame = await run_walk(
        session,
        FRAME_WALK,
        {
            "entries": vtable["vtable_entries"],
            "dispatches": FRAME_ACTIVATE_DISPATCHES[platform],
            "set_minimized_dispatch": FRAME_SET_MINIMIZED_DISPATCH[platform],
        },
    )
    if frame.get("error") or "frame_activate" not in frame:
        if debug:
            print(f"  {FRAME_ACTIVATE_SYMBOL}: locator failed: {frame.get('error', frame)}")
        return False
    function = await inspect_unique_function(session, FRAME_ACTIVATE_NAME, frame["frame_activate"], image_base, debug)
    if function is None:
        return False
    frame_index = int(frame["frame_index"])
    payloads[FRAME_ACTIVATE_SYMBOL] = {
        field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size")
    }
    payloads[FRAME_ACTIVATE_SYMBOL].update(
        vtable_name=FRAME_CLASS,
        vfunc_index=frame_index,
        vfunc_offset=hex(frame_index * 4),
        vfunc_sig=function["func_sig"],
    )
    if function.get("func_sig_allow_across_function_boundary"):
        payloads[FRAME_ACTIVATE_SYMBOL]["vfunc_sig_allow_across_function_boundary"] = True
    for name, payload in payloads.items():
        write_func_yaml(outputs[name], payload)
    return True
