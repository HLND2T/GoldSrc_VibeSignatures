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
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_func_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import RICHTEXT_BOM, run_walk

LOADCS_SYMBOL = "ClientVGUI_LoadControlSettings"
SETTEXTA_SYMBOL = "ClientVGUI_RichText_SetTextA"
SETTEXTW_SYMBOL = "ClientVGUI_RichText_SetTextW"
LOADMAP_SYMBOL = "TeamMenu_LoadMapPage"
TEAMMENU_LITERAL = "Resource/UI/TeamMenu.res"
MAPS_LITERAL = "maps/%s.txt"

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


async def _emit_function(session, name, target, image_base, debug):
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
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in targets}
    if not all(outputs.values()):
        return False
    payloads = {}
    for name, (key, function_name) in targets.items():
        function = await _emit_function(session, function_name, result[key], image_base, debug)
        if function is None:
            return False
        payloads[name] = {
            field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")
        }
        if function.get("func_sig_allow_across_function_boundary"):
            payloads[name]["func_sig_allow_across_function_boundary"] = True
    for name, payload in payloads.items():
        write_func_yaml(outputs[name], payload)
    return True
