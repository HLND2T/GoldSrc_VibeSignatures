#!/usr/bin/env python3
"""Recover CVideoMode_Common::UpdateWindowPosition from the OpenGL vtable.

IVideoMode layout grows by one slot on HL25: ``PlayStartupSequence`` is inserted
after ``Init`` and owns ``-novid``. That member is present on hl-10210 and
absent on GoldSrc, BLOB, CoF, and SvEngine. UpdateWindowPosition is therefore
index 11 (offset 0x2C) when any CVideoMode_OpenGL slot owns ``-novid``, and
index 10 (offset 0x28) otherwise. The selected body must make at least one
in-image direct call (``VID_UpdateWindowVars``).
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    write_func_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

FUNC_NAME = "CVideoMode_Common_UpdateWindowPosition"
VTABLE_STEM = "CVideoMode_OpenGL_vtable"
VTABLE_CLASS = "CVideoMode_OpenGL"
NOVID_LITERAL = "-novid"
INDEX_DEFAULT = 10
INDEX_HL25 = 11

LOCATE = r"""
ENTRIES = values['entries']
LITERAL = values['literal']
INDEX_DEFAULT = int(values['index_default'])
INDEX_HL25 = int(values['index_hl25'])

def owner_start(ea):
    fn = ida_funcs.get_func(int(ea))
    return int(fn.start_ea) if fn is not None else None

owners = set()
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) != LITERAL:
        continue
    for xref in idautils.XrefsTo(int(item.ea), 0):
        start = owner_start(xref.frm)
        if start is not None:
            owners.add(start)

novid_slots = []
for raw_index, raw_ea in ENTRIES.items():
    ea = int(raw_ea, 0) if isinstance(raw_ea, str) else int(raw_ea)
    if ea in owners:
        novid_slots.append(int(raw_index))

index = INDEX_HL25 if novid_slots else INDEX_DEFAULT
if index not in {int(key) for key in ENTRIES} and str(index) not in ENTRIES:
    result = {'error': 'UpdateWindowPosition index is missing from the vtable', 'novid_slots': novid_slots}
else:
    raw = ENTRIES.get(index, ENTRIES.get(str(index)))
    target = int(raw, 0) if isinstance(raw, str) else int(raw)
    calls = direct_calls(target)
    if not calls:
        result = {'error': 'selected vfunc has no in-image direct call', 'index': index, 'target': hex(target)}
    else:
        result = {
            'pointer_size': 4,
            'index': index,
            'target': hex(target),
            'novid_slots': novid_slots,
            'direct_callees': len(calls),
        }
"""


def _load_vtable(new_binary_dir, platform):
    path = Path(new_binary_dir) / f"{VTABLE_STEM}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("vtable_class") != VTABLE_CLASS:
        return None
    entries = artifact.get("vtable_entries") or {}
    if not entries:
        return None
    return {int(index): str(value) for index, value in entries.items()}


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
    _ = old_yaml_map
    output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if output is None:
        return False
    entries = _load_vtable(new_binary_dir, platform)
    if entries is None:
        if debug:
            print(f"{skill_name}: missing {VTABLE_STEM} artifact")
        return False
    located = await run_walk(
        session,
        LOCATE,
        {
            "entries": {str(index): value for index, value in entries.items()},
            "literal": NOVID_LITERAL,
            "index_default": INDEX_DEFAULT,
            "index_hl25": INDEX_HL25,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    try:
        index = int(located["index"])
        target = int(located["target"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if target < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, target, image_base, FUNC_NAME)
    allow_across = False
    if not function or int(function.get("func_va", "0"), 0) != target:
        function = await _inspect_function_via_mcp(
            session, target, image_base, FUNC_NAME, allow_across_function_boundary=True
        )
        allow_across = bool(function and int(function.get("func_va", "0"), 0) == target)
    if not function or int(function["func_va"], 0) != target:
        if debug:
            print(f"{skill_name}: failed to inspect slot {index} at {hex(target)}")
        return False
    payload = {
        "func_name": FUNC_NAME,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "vtable_name": VTABLE_CLASS,
        "vfunc_offset": hex(index * 4),
        "vfunc_index": index,
        "vfunc_sig": function["func_sig"],
    }
    if allow_across:
        payload["vfunc_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    if debug:
        print(f"{skill_name}: va={function['func_va']} index={index} novid_slots={located.get('novid_slots')}")
    return True
