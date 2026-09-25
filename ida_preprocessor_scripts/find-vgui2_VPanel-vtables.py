#!/usr/bin/env python3
"""Resolve the IPanel wrapper and internal VPanel primary tables via RTTI."""

from ida_analyze_util import _output_for_symbol, write_vtable_yaml
from ida_preprocessor_scripts._vgui_paint_common import walk


LOCATE = r"""
strings=idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C],minlen=4)
if not any(str(s)=='VGUI_Panel007' for s in strings):
    raise ValueError('IPanel interface registration absent')
result=table_for(values['class'])
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir, platform, image_base
    for stem, class_name in (("vgui2_VPanelWrapper_vtable", "VPanelWrapper"), ("vgui2_VPanel_vtable", "vgui2::VPanel")):
        table = await walk(session, LOCATE, {"class": class_name})
        output = _output_for_symbol(expected_outputs, stem)
        if output is None or table.get("error") or not table.get("vtable_entries"):
            if debug:
                print(table)
            return False
        write_vtable_yaml(output, table)
    return True
