#!/usr/bin/env python3
"""Recover the engine's primary vgui2::Panel table from current RTTI."""

from ida_analyze_util import _output_for_symbol, write_vtable_yaml
from ida_preprocessor_scripts._vgui_paint_common import walk


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir, platform, image_base
    table = await walk(session, "result=table_for('vgui2::Panel')", {})
    output = _output_for_symbol(expected_outputs, "vgui2_Panel_vtable")
    if output is None or table.get("error") or not table.get("vtable_entries"):
        if debug:
            print(table)
        return False
    write_vtable_yaml(output, table)
    return True
