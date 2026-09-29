#!/usr/bin/env python3
"""Locate vgui2::Panel::Init in a module through its layout-default stores.

``vgui2::Panel::Init`` writes its member defaults around the ``_proportional``
store ``mov dword ptr [reg+0x24], 2`` and begins by resolving the ``ivgui()`` /
``ipanel()`` interface pointers and dispatching vtable-indirect calls through
them. MetaHookSv located this function through its callers'
``push 0x18; push 0x40; push 0; push 0`` setup, which GCC constprop removes, so
that anchor is not cross-platform.

Candidates originate at every ``_proportional`` store. The finder keeps code
regions that (a) also store to at least three of the neighboring layout
offsets and (b) contain at least two interface-dispatch idioms in their head:
``call getter; mov vtable, [interface]`` followed by a direct vtable call or a
slot load and register call. This rejects the sibling
``CAvatarImagePanel::SetPlayer`` and TextEntry-like layout functions that share
the single store. Optimized Linux builds keep both the exported full-body
``Panel::Init`` and a constprop clone that the constructors actually call. The
clone takes this in eax and specializes the four dimensions, so it is not ABI
compatible with the ordinary entry. Require all five incoming cdecl stack
arguments on Linux, independently of symbol names or internal caller counts.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_func_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import PANEL_INIT_STORE_OFFSETS, run_walk

FUNCTION_NAME = "vgui2::Panel::Init(int, int, int, int)"
OUTPUT_SYMBOLS = ("vgui2_Panel_Init", "ClientVGUI_Panel_Init")

WALK = r"""
import ida_frame, ida_idp

def register_name(operand):
    return (ida_idp.get_reg_name(int(operand.reg), 4) or '').lower()


def memory_base(operand):
    if operand.type not in (ida_ua.o_displ, ida_ua.o_phrase):
        return None
    if int(operand.specflag1):
        sib = int(operand.specflag2)
        if (sib >> 3) & 7 != 4:
            return None
        return (ida_idp.get_reg_name(sib & 7, 4) or '').lower()
    return register_name(operand)


def memory_disp(operand):
    return int(operand.addr) if operand.type == ida_ua.o_displ else 0


def interface_dispatch_idioms(items):
    # Panel::Init resolves ivgui()/ipanel() through a direct getter call, loads
    # the returned interface vtable, and calls a positive vtable slot.
    idioms = 0
    for index, insn_ea in enumerate(items):
        insn = idautils.DecodeInstruction(insn_ea)
        if insn is None or insn.get_canon_mnem() != 'call':
            continue
        if insn.ops[0].type not in (ida_ua.o_near, ida_ua.o_far):
            continue
        vtable_reg = None
        target_reg = None
        for follower in items[index + 1:index + 9]:
            nxt = idautils.DecodeInstruction(follower)
            if nxt is None:
                continue
            mnemonic = nxt.get_canon_mnem()
            if mnemonic == 'call':
                operand = nxt.ops[0]
                if vtable_reg and (
                    (memory_base(operand) == vtable_reg and memory_disp(operand) > 0)
                    or (operand.type == ida_ua.o_reg and register_name(operand) == target_reg)
                ):
                    idioms += 1
                break
            if mnemonic != 'mov' or nxt.ops[0].type != ida_ua.o_reg:
                continue
            dest_reg = register_name(nxt.ops[0])
            source = nxt.ops[1]
            source_base = memory_base(source)
            source_disp = memory_disp(source)
            if source_base not in (None, 'esp', 'ebp') and source_disp == 0:
                vtable_reg = dest_reg
                target_reg = None
            elif vtable_reg and source_base == vtable_reg and source_disp > 0:
                target_reg = dest_reg
            elif dest_reg == vtable_reg:
                vtable_reg = None
                target_reg = None
            elif dest_reg == target_reg:
                target_reg = None
    return idioms


def has_cdecl_arguments(function_ea, items):
    # Normalize esp-relative reads to entry esp using IDA's stack deltas.
    # The supported GCC bodies read this, x, y, w, h from those five slots;
    # constprop clones instead take this in eax and hardcode the dimensions.
    function = ida_funcs.get_func(function_ea)
    arguments = set()
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if insn is None or insn.get_canon_mnem() != 'mov':
            continue
        dest, source = insn.ops[0], insn.ops[1]
        if (dest.type != ida_ua.o_reg or source.type != ida_ua.o_displ
                or source.dtype != ida_ua.dt_dword):
            continue
        # ESP base, no SIB index. Do not mistake an indexed object read for
        # an incoming argument merely because the printed operand contains esp.
        if not source.specflag1 or int(source.specflag2) & 0x3F != 0x24:
            continue
        arguments.add(int(source.addr) + int(ida_frame.get_spd(function, ea)))
    return set(values['cdecl_argument_offsets']).issubset(arguments)


def candidate_body(store_ea):
    # Some older ServerBrowser IDBs merge many adjacent functions into one.
    # A return followed by alignment separates the true entry from its owner.
    owner = ida_funcs.get_func(store_ea)
    items = function_body(owner.start_ea)
    store_index = items.index(store_ea)
    for index in range(store_index - 1, -1, -1):
        previous = idautils.DecodeInstruction(items[index])
        if (previous is not None and previous.get_canon_mnem().startswith('ret')
                and items[index] + previous.size < items[index + 1]):
            head_index = index + 1
            break
    else:
        head_index = 0
    head = items[head_index]
    if head == owner.start_ea:
        return head, owner.start_ea, owner.end_ea, items
    for index in range(store_index, len(items)):
        insn = idautils.DecodeInstruction(items[index])
        if insn is not None and insn.get_canon_mnem().startswith('ret'):
            return head, owner.start_ea, items[index] + insn.size, items[head_index:index + 1]
    return None


store_sites = set()
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
            store_sites.add(int(insn_ea))

if not store_sites:
    raise ValueError('no candidate holds the _proportional store')

neighborhood = set(values['neighborhood'])
matches = []
diagnostics = []
for store_ea in sorted(store_sites):
    region = candidate_body(store_ea)
    if region is None:
        diagnostics.append((hex(store_ea), 'aligned candidate has no return'))
        continue
    candidate, owner_ea, end_ea, items = region
    store_offsets = set()
    for insn_ea in items:
        insn = idautils.DecodeInstruction(insn_ea)
        if insn is None or idautils.DecodeInstruction(insn_ea).get_canon_mnem() not in ('mov', 'movzx', 'and'):
            continue
        dest = insn.ops[0]
        if dest.type == ida_ua.o_displ:
            store_offsets.add(int(dest.addr))
    neighbor_count = len(neighborhood & store_offsets)
    cdecl_ok = values['platform'] != 'linux' or has_cdecl_arguments(candidate, items)
    idiom_count = interface_dispatch_idioms(items[:values['head_span']])
    diagnostics.append((hex(candidate), neighbor_count, cdecl_ok, idiom_count))
    if neighbor_count < values['neighbor_minimum'] or not cdecl_ok or idiom_count < values['idiom_minimum']:
        continue
    matches.append((candidate, owner_ea, end_ea))

if not matches:
    raise ValueError('no candidate satisfies the Panel::Init layout and dispatch filters: ' + repr(diagnostics))
matches = sorted(set(matches))
if len(matches) != 1:
    raise ValueError('Panel::Init candidate is not unique: ' + repr([hex(match[0]) for match in matches]))
candidate, owner_ea, end_ea = matches[0]
if candidate != owner_ea:
    if not ida_funcs.del_func(owner_ea) or not ida_funcs.add_func(candidate, end_ea):
        raise ValueError('could not restore Panel::Init boundary at ' + hex(candidate))
    recovered = ida_funcs.get_func(candidate)
    if recovered is None or recovered.start_ea != candidate or recovered.end_ea != end_ea:
        raise ValueError('restored Panel::Init boundary disagrees at ' + hex(candidate))
result = {'panel_init': candidate}
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
    outputs = [_output_for_symbol(expected_outputs, symbol) for symbol in OUTPUT_SYMBOLS]
    outputs = [output for output in outputs if output is not None]
    if len(outputs) != 1:
        if debug:
            print(f"  {FUNCTION_NAME}: expected exactly one Panel::Init output, got {outputs}")
        return False
    located = await run_walk(
        session,
        WALK,
        {
            "platform": platform,
            "cdecl_argument_offsets": [4, 8, 12, 16, 20],
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
            print(f"  {FUNCTION_NAME}: locator failed: {located.get('error', located)}")
        return False
    target = int(located["panel_init"])
    function = await _inspect_function_via_mcp(session, target, image_base, FUNCTION_NAME)
    allow_across = function is None or not function.get("func_sig")
    if allow_across:
        function = await _inspect_function_via_mcp(
            session, target, image_base, FUNCTION_NAME, allow_across_function_boundary=True
        )
        if function is not None:
            function["func_sig_allow_across_function_boundary"] = True
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {FUNCTION_NAME}: no unique signature at {hex(target)}")
        return False
    output = outputs[0]
    payload = {field: function[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
