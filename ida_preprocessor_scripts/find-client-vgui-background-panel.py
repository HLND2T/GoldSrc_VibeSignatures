#!/usr/bin/env python3
"""Recover the CS background panel through its constructor's resource name.

``CounterStrikeViewport::CCSBackGroundPanel`` uniquely owns
``Resource/UI/BackgroundPanel.res``. Its constructor installs the terminal
derived-class vptr, and its unique direct caller is ``CounterStrikeViewport::Start``.
That caller stores the constructed pointer in both its own member and the
``TeamFortressViewport`` background-panel member. The two stores recover the
derived member offset without assuming either compiler's object layout.

The panel's ``Activate`` overrides the ``vgui2::Frame::Activate`` slot. The
separately verified Frame artifact supplies the slot for the *current* binary;
the override body must call ``Frame::Activate`` after ``Panel::SetPos``.
"""

from pathlib import Path

import yaml

from ida_analyze_util import (
    _output_for_symbol,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_struct_offset_yaml,
    write_vtable_yaml,
)
from ida_preprocessor_scripts._client_vgui_private_common import (
    FRAME_CLASS,
    FRAME_VTABLE_ALIASES,
    inspect_unique_function,
    run_walk,
)

START_SYMBOL = "CounterStrikeViewport_Start"
MEMBER_SYMBOL = "CClientVGUI_m_pCSBackGroundPanel"
VTABLE_SYMBOL = "CCSBackGroundPanel"
ACTIVATE_SYMBOL = "CCSBackGroundPanel_Activate"
FRAME_SYMBOL = "ClientVGUI_Frame_Activate"
VIEWPORT_CLASS = "CounterStrikeViewport"
BACKGROUND_CLASS = "CounterStrikeViewport::CCSBackGroundPanel"
BACKGROUND_LITERAL = "Resource/UI/BackgroundPanel.res"
BACKGROUND_VTABLE_ALIASES = {
    "windows": ["??_7CCSBackGroundPanel@CounterStrikeViewport@@6B@"],
    "linux": ["_ZTVN21CounterStrikeViewport18CCSBackGroundPanelE"],
}

WALK = r"""
evidence = string_owner_evidence(values['literal'])
ctor = require_single_owner(evidence, values['literal'])

# The constructor first installs its CBackGroundPanel vptr, then the final
# CCSBackGroundPanel vptr. IDA resolves R_386_32 relocated ELF immediates to
# the vtable address point, so this test works on PE and ELF alike.
vptr_sites = []
for ea in function_body(ctor):
    insn = idautils.DecodeInstruction(ea)
    if insn is None or insn.get_canon_mnem() != 'mov':
        continue
    dest, source = insn.ops[0], insn.ops[1]
    if (dest.type in (ida_ua.o_displ, ida_ua.o_phrase) and int(dest.addr) == 0
            and source.type == ida_ua.o_imm and imm_value(source) == values['background_vtable']):
        vptr_sites.append(int(ea))
if len(vptr_sites) != 1:
    raise ValueError('derived vptr store is not unique: ' + repr([hex(ea) for ea in vptr_sites]))

call_sites = []
for ref in idautils.XrefsTo(ctor, 0):
    site = int(ref.frm)
    if not ida_bytes.is_code(ida_bytes.get_flags(site)) or direct_call_target(site) != ctor:
        continue
    owner = ida_funcs.get_func(site)
    if owner is not None:
        call_sites.append((site, int(owner.start_ea)))
if len(call_sites) != 1:
    raise ValueError('constructor direct caller is not unique: ' + repr(call_sites))
call_site, start = call_sites[0]

# Find the paired stores of the newly constructed pointer before the next
# call. The larger displacement is the derived-class member; the smaller one
# is TeamFortressViewport::m_pBackGround. Neither value is a discovery constant.
items = function_body(start)
if call_site not in items:
    raise ValueError('constructor call is outside its owning function')
stores = []
for ea in items[items.index(call_site) + 1:]:
    if direct_call_target(ea) is not None:
        break
    insn = idautils.DecodeInstruction(ea)
    if insn is None or insn.get_canon_mnem() != 'mov':
        continue
    dest, source = insn.ops[0], insn.ops[1]
    if (dest.type == ida_ua.o_displ and dest.dtype == ida_ua.dt_dword
            and source.type == ida_ua.o_reg and int(dest.addr) > 0):
        stores.append((int(ea), int(dest.addr), int(dest.reg), int(source.reg)))
pairs = []
for first_index, first in enumerate(stores):
    for second in stores[first_index + 1:]:
        if first[2:] == second[2:] and first[1] > second[1]:
            pairs.append((first, second))
if len(pairs) != 1:
    raise ValueError('paired Start stores are not unique: ' + repr(stores))
member_store, base_store = pairs[0]

activate = int(values['background_activate'])
if not executable_target(activate) or activate == values['frame_activate']:
    raise ValueError('background Activate slot is invalid')
direct_calls = [direct_call_target(ea) for ea in function_body(activate)]
direct_calls = [target for target in direct_calls if target is not None]
if len(direct_calls) < 2 or direct_calls[1] != values['frame_activate']:
    raise ValueError('background Activate does not call Frame::Activate after SetPos')

result = {
    'ctor': ctor,
    'start': start,
    'start_call': call_site,
    'member_offset': member_store[1],
    'member_store': member_store[0],
    'base_offset': base_store[1],
    'vptr_store': vptr_sites[0],
    'activate': activate,
}
"""


def _read_frame_artifact(new_binary_dir, platform):
    path = Path(new_binary_dir) / f"{FRAME_SYMBOL}.{platform}.yaml"
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        if payload.get("func_name") != "vgui2::Frame::Activate()":
            return None
        index = int(payload["vfunc_index"])
        va = int(payload["func_va"], 0)
        if int(payload["vfunc_offset"], 0) != index * 4:
            return None
        return index, va
    except (OSError, AttributeError, KeyError, TypeError, ValueError, yaml.YAMLError):
        return None


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
    outputs = {
        name: _output_for_symbol(expected_outputs, name)
        for name in (START_SYMBOL, MEMBER_SYMBOL, VTABLE_SYMBOL, ACTIVATE_SYMBOL)
    }
    if not all(outputs.values()):
        return False
    frame = _read_frame_artifact(new_binary_dir, platform)
    if frame is None:
        if debug:
            print(f"  {ACTIVATE_SYMBOL}: required Frame::Activate artifact is missing or invalid")
        return False
    frame_index, frame_va = frame
    frame_vtable = await preprocess_vtable_via_mcp(
        session, FRAME_CLASS, image_base, platform, symbol_aliases=FRAME_VTABLE_ALIASES[platform]
    )
    background_vtable = await preprocess_vtable_via_mcp(
        session,
        BACKGROUND_CLASS,
        image_base,
        platform,
        symbol_aliases=BACKGROUND_VTABLE_ALIASES[platform],
    )
    if frame_vtable is None or background_vtable is None:
        if debug:
            print(f"  {VTABLE_SYMBOL}: Frame or background vtable was not found")
        return False
    frame_slot = frame_vtable["vtable_entries"].get(frame_index)
    background_slot = background_vtable["vtable_entries"].get(frame_index)
    if frame_slot is None or background_slot is None or int(frame_slot, 0) != frame_va:
        if debug:
            print(f"  {ACTIVATE_SYMBOL}: current Frame slot does not match its input artifact")
        return False
    background_va = int(background_slot, 0)
    located = await run_walk(
        session,
        WALK,
        {
            "literal": BACKGROUND_LITERAL,
            "background_vtable": int(background_vtable["vtable_va"], 0),
            "background_activate": background_va,
            "frame_activate": frame_va,
        },
    )
    if located.get("error") or "member_offset" not in located:
        if debug:
            print(f"  {VTABLE_SYMBOL}: locator failed: {located.get('error', located)}")
        return False
    start = await inspect_unique_function(
        session, "CounterStrikeViewport::Start()", located["start"], image_base, debug
    )
    activate = await inspect_unique_function(
        session, f"{BACKGROUND_CLASS}::Activate()", located["activate"], image_base, debug
    )
    if start is None or activate is None:
        return False

    start_payload = {field: start[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if start.get("func_sig_allow_across_function_boundary"):
        start_payload["func_sig_allow_across_function_boundary"] = True
    member_payload = {
        "struct_name": VIEWPORT_CLASS,
        "member_name": "m_pCSBackGround",
        "offset": hex(located["member_offset"]),
        "size": 4,
    }
    vtable_payload = {key: value for key, value in background_vtable.items() if not key.startswith("_")}
    if platform == "linux":
        vtable_payload["vtable_symbol"] += " + 0x8"
    activate_payload = {field: activate[field] for field in ("func_name", "func_va", "func_rva", "func_size")}
    activate_payload.update(
        vtable_name=BACKGROUND_CLASS,
        vfunc_index=frame_index,
        vfunc_offset=hex(frame_index * 4),
        vfunc_sig=activate["func_sig"],
    )
    if activate.get("func_sig_allow_across_function_boundary"):
        activate_payload["vfunc_sig_allow_across_function_boundary"] = True

    write_func_yaml(outputs[START_SYMBOL], start_payload)
    write_struct_offset_yaml(outputs[MEMBER_SYMBOL], member_payload)
    write_vtable_yaml(outputs[VTABLE_SYMBOL], vtable_payload)
    write_func_yaml(outputs[ACTIVATE_SYMBOL], activate_payload)
    return True
