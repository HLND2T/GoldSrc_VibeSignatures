#!/usr/bin/env python3
"""Locate the client-side vgui2::Panel::Init through its layout-default stores.

``vgui2::Panel::Init`` writes its member defaults around the ``_proportional``
store ``mov dword ptr [reg+0x24], 2`` and begins by resolving the ``ivgui()`` /
``ipanel()`` interface pointers and dispatching vtable-indirect calls through
them. MetaHookSv located this function through its callers'
``push 0x18; push 0x40; push 0; push 0`` setup, which GCC constprop removes, so
that anchor is not cross-platform.

Candidates are every function holding the ``_proportional`` store. The finder
keeps those that (a) also store to at least three of the neighboring layout
offsets and (b) contain at least two ``call getter; mov reg, [eax]; call [reg+disp]``
interface-dispatch idioms in their head — rejecting the sibling
``CAvatarImagePanel::SetPlayer`` and TextEntry-like layout functions that share
the single store. Optimized Linux builds keep both the exported full-body
``Panel::Init`` and a constprop clone that the constructors actually call; the
candidate with internal direct callers wins there, matching the entry that
executes at runtime.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_func_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import PANEL_INIT_STORE_OFFSETS, run_walk

SYMBOL = "ClientVGUI_Panel_Init"

WALK = r"""
def indirect_call_disp(ea):
    insn = idautils.DecodeInstruction(ea)
    if insn is None or idautils.DecodeInstruction(ea).get_canon_mnem() != 'call':
        return None
    operand = insn.ops[0]
    if operand.type in (ida_ua.o_displ, ida_ua.o_phrase) and int(operand.addr) > 0:
        return int(operand.addr)
    return None


def interface_dispatch_idioms(items):
    # Panel::Init resolves ivgui()/ipanel() through a direct getter call, loads
    # the returned interface vtable (mov reg, [eax]), and vcalls through it.
    idioms = 0
    for index, insn_ea in enumerate(items):
        insn = idautils.DecodeInstruction(insn_ea)
        if insn is None or idautils.DecodeInstruction(insn_ea).get_canon_mnem() != 'call':
            continue
        if insn.ops[0].type not in (ida_ua.o_near, ida_ua.o_far):
            continue
        loaded = False
        vcalled = False
        for follower in items[index + 1:index + 9]:
            nxt = idautils.DecodeInstruction(follower)
            if nxt is None:
                continue
            mnemonic = idautils.DecodeInstruction(follower).get_canon_mnem()
            if mnemonic == 'mov' and nxt.ops[0].type == ida_ua.o_reg and nxt.ops[1].type in (ida_ua.o_displ, ida_ua.o_phrase) and int(nxt.ops[1].addr) == 0:
                loaded = True
            elif mnemonic == 'call' and indirect_call_disp(follower) is not None:
                if loaded:
                    vcalled = True
                break
            elif mnemonic == 'call':
                break
        if vcalled:
            idioms += 1
    return idioms


def internal_callers(function_ea):
    return [int(ref) for ref in idautils.CodeRefsTo(int(function_ea), 0)
            if ida_funcs.get_func(int(ref)) is None or int(ida_funcs.get_func(int(ref)).start_ea) != int(function_ea)]


candidates = set()
for function_ea in idautils.Functions():
    for insn_ea in function_body(function_ea):
        insn = idautils.DecodeInstruction(insn_ea)
        if insn is None:
            continue
        if idautils.DecodeInstruction(insn_ea).get_canon_mnem() != 'mov' or len(insn.ops) < 2:
            continue
        dest, source = insn.ops[0], insn.ops[1]
        if (dest.type in (ida_ua.o_displ, ida_ua.o_phrase) and int(dest.addr) == values['proportional_offset']
                and source.type == ida_ua.o_imm and imm_value(source) == values['proportional_value']):
            candidates.add(int(function_ea))
            break

if not candidates:
    raise ValueError('no candidate holds the _proportional store')

neighborhood = set(values['neighborhood'])
matches = []
for candidate in sorted(candidates):
    store_offsets = set()
    for insn_ea in function_body(candidate):
        insn = idautils.DecodeInstruction(insn_ea)
        if insn is None or idautils.DecodeInstruction(insn_ea).get_canon_mnem() not in ('mov', 'movzx', 'and'):
            continue
        dest = insn.ops[0]
        if dest.type == ida_ua.o_displ:
            store_offsets.add(int(dest.addr))
    if len(neighborhood & store_offsets) < values['neighbor_minimum']:
        continue
    items = function_body(candidate)
    if interface_dispatch_idioms(items[:values['head_span']]) < values['idiom_minimum']:
        continue
    matches.append(candidate)

if not matches:
    raise ValueError('no candidate satisfies the Panel::Init layout and dispatch filters')
if len(matches) > 1:
    with_callers = [candidate for candidate in matches if internal_callers(candidate)]
    if len(with_callers) == 1:
        matches = with_callers
if len(matches) != 1:
    raise ValueError('Panel::Init candidate is not unique: ' + repr([hex(match) for match in matches]))
result = {'panel_init': matches[0]}
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
        {
            "proportional_offset": 0x24,
            "proportional_value": 2,
            "neighborhood": sorted(set(PANEL_INIT_STORE_OFFSETS) - {0x24}),
            "neighbor_minimum": 3,
            "idiom_minimum": 2,
            "head_span": 48,
        },
    )
    if located.get("error") or "panel_init" not in located:
        if debug:
            print(f"  {SYMBOL}: locator failed: {located.get('error', located)}")
        return False
    target = int(located["panel_init"])
    function = await _inspect_function_via_mcp(session, target, image_base, SYMBOL)
    allow_across = function is None or not function.get("func_sig")
    if allow_across:
        function = await _inspect_function_via_mcp(
            session, target, image_base, SYMBOL, allow_across_function_boundary=True
        )
        if function is not None:
            function["func_sig_allow_across_function_boundary"] = True
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {SYMBOL}: no unique signature at {hex(target)}")
        return False
    output = _output_for_symbol(expected_outputs, SYMBOL)
    if not output:
        return False
    payload = {field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
