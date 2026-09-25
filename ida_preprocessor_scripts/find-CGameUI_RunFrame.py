#!/usr/bin/env python3
"""Find the gameui RunFrame override by its own ActiveGameName message."""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._vgui_paint_common import walk


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    name = "CGameUI_RunFrame"
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[name],
        func_xrefs=[dict(func_name=name, xref_strings=["FULLMATCH:ActiveGameName"])],
        generate_yaml_desired_fields=[(name, ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, name)
    data = _load_yaml_mapping(output)
    located = await walk(
        session,
        "t=table_for('CGameUI'); result={'slots':[i for i,e in t['vtable_entries'].items() if int(e,0)==values['ea']]}",
        dict(ea=int(data["func_va"], 0)),
    )
    slots = located.get("slots", [])
    if len(slots) != 1:
        return False
    data.update(
        func_name="CGameUI::RunFrame()", vtable_name="CGameUI", vfunc_index=slots[0], vfunc_offset=hex(slots[0] * 4)
    )
    write_func_yaml(output, data)
    return True
