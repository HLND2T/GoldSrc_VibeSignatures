#!/usr/bin/env python3
"""Locate the native Windows CGame window methods (engine/sys_mainwind.cpp).

CreateGameWindow owns both Valve001 and game.ico and belongs to the current
CGame table. Do not require 0x84CB0000 bytes: CoF computes that style with
OR/AND instructions instead. WindowProc owns SC_CLOSE and SC_SCREENSAVE
immediates and dispatches GetQuitting through the verified eng global.
SDL engines do not register this finder. Signatures validate discovered
functions; neither old artifacts nor reference-build slots select an entry.
"""

from ida_analyze_util import (
    _FUNCTION_OWNER_RECOVERY_PY_EVAL,
    _output_for_symbol,
    preprocess_func_xrefs_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._engine_runtime_slots import DATA_REFERENCED_ENTRY_RECOVERY_PY
from ida_preprocessor_scripts._vgui_paint_common import artifact, walk

RECOVER = (
    "import ida_auto, ida_bytes, ida_funcs, ida_segment, ida_ua, idaapi, idautils, idc, json\n"
    + _FUNCTION_OWNER_RECOVERY_PY_EVAL
    + DATA_REFERENCED_ENTRY_RECOVERY_PY
    + r"""
result = dict(checked=_recover_data_referenced_entries(values['entries']))
"""
)
CHECK_WINDOW = r"""
constants = set()
for ea in idautils.FuncItems(values['owner']):
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea) or insn.get_canon_mnem() != 'cmp':
        continue
    constants.update(int(op.value) & 0xffffffff for op in insn.ops if op.type == ida_ua.o_imm)
eng = ('load', ('const', values['eng']), 0)
flow = flow_at(values['owner'], 'windows')
guards = []
for call in flow['calls']:
    targets = virtual_targets(call['target'])
    if len(targets) == 1 and targets[0][0] == eng and targets[0][1] == values['slot'] and call['args'][:1] == [eng]:
        guards.append(call['ea'])
result = dict(valid={0xf060, 0xf140} <= constants and bool(guards), guards=guards)
"""
FIELDS = ("func_name", "func_va", "func_rva", "func_size", "func_sig")


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    names = ("CGame_CreateGameWindow", "CGame_WindowProc")
    if platform != "windows" or any(_output_for_symbol(expected_outputs, name) is None for name in names):
        return False
    table = artifact(new_binary_dir, "CGame_vtable", platform)
    eng = artifact(new_binary_dir, "eng", platform)
    quitting = artifact(new_binary_dir, "IEngine_GetQuitting", platform)
    if not table or table.get("vtable_class") != "CGame" or not eng or not quitting:
        return False
    try:
        entries = {int(index): int(address, 0) for index, address in table["vtable_entries"].items()}
        eng_address = int(eng["gv_va"], 0)
        slot = int(quitting["vfunc_offset"], 0)
        if slot < 0 or slot % 4 or slot != quitting["vfunc_index"] * 4:
            return False
    except (KeyError, TypeError, ValueError):
        return False
    recovered = await run_walk(session, RECOVER, {"entries": list(entries.values())})
    if not recovered.get("checked"):
        if debug:
            print(f"{skill_name}: exact vtable entry recovery failed: {recovered}")
        return False
    results = {}
    for name, strings, signatures, vtable in (
        (names[0], ["FULLMATCH:Valve001", "FULLMATCH:game.ico"], [], "CGame_vtable"),
        (names[1], [], ["60 F0 00 00", "40 F1 00 00"], None),
    ):
        found = await preprocess_func_xrefs_via_mcp(
            session,
            name,
            xref_strings=strings,
            xref_gvs=[],
            xref_signatures=signatures,
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            vtable_class=vtable,
        )
        if not found or not all(found.get(field) for field in FIELDS):
            if debug:
                print(f"{skill_name}: incomplete unique xref result for {name}: {found}")
            return False
        results[name] = {field: found[field] for field in FIELDS}
    create = results[names[0]]
    indices = [index for index, address in entries.items() if address == int(create["func_va"], 0)]
    if len(indices) != 1:
        return False
    create.update(vtable_name="CGame", vfunc_offset=hex(indices[0] * 4), vfunc_index=indices[0])
    window = results[names[1]]
    checked = await walk(session, CHECK_WINDOW, {"owner": int(window["func_va"], 0), "eng": eng_address, "slot": slot})
    if not checked.get("valid"):
        if debug:
            print(f"{skill_name}: WindowProc instruction/receiver validation failed: {checked}")
        return False
    for name, data in results.items():
        data["func_name"] = name.replace("CGame_", "CGame::", 1)
        write_func_yaml(_output_for_symbol(expected_outputs, name), data)
    if debug:
        print(
            f"{skill_name}: create={create['func_va']} window={window['func_va']} quitting guards={checked['guards']}"
        )
    return True
