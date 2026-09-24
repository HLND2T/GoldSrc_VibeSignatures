#!/usr/bin/env python3
"""Find the primary engine text-surface vtables through class RTTI.

The factories advertise EngineSurface007 and VGUI_Surface026. The primary
BaseUISurface vtable is required: Windows also has an IMouseControl secondary
table whose name shares the class prefix.
"""

from ida_analyze_util import _output_for_symbol, preprocess_vtable_via_mcp, write_vtable_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk


VERIFY_FACTORY = r"""
LITERALS = values['literals']
found = set()
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)
for item in strings:
    text = str(item)
    if text in LITERALS:
        found.add(text)
result = {'found': sorted(found)} if found == set(LITERALS) else {'error': 'surface factory literal missing'}
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
    checked = await run_walk(session, VERIFY_FACTORY, {"literals": ["EngineSurface007", "VGUI_Surface026"]})
    if checked.get("error"):
        return False
    for class_name in ("EngineSurface", "BaseUISurface"):
        output = _output_for_symbol(expected_outputs, f"{class_name}_vtable")
        table = await preprocess_vtable_via_mcp(session, class_name, image_base, platform, debug=debug)
        if output is None or table is None:
            return False
        symbol = str(table.get("vtable_symbol") or "")
        expected = f"??_7{class_name}@@6B@" if platform == "windows" else f"_ZTV{len(class_name)}{class_name}"
        if symbol != expected and symbol != f"{expected} + 0x8":
            if debug:
                print(f"{skill_name}: unexpected {class_name} vtable symbol: {symbol}")
            return False
        entries = table.get("vtable_entries") or {}
        minimum_slots = 60 if class_name == "BaseUISurface" else 23
        if len(entries) < minimum_slots:
            return False
        write_vtable_yaml(
            output,
            {
                "vtable_class": class_name,
                "vtable_symbol": symbol,
                "vtable_va": table["vtable_va"],
                "vtable_rva": table["vtable_rva"],
                "vtable_size": table["vtable_size"],
                "vtable_numvfunc": table["vtable_numvfunc"],
                "vtable_entries": entries,
            },
        )
    return True
