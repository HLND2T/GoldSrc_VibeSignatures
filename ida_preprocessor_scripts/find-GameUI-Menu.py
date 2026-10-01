#!/usr/bin/env python3
"""Locate Menu's primary RTTI table and inherit the current PerformLayout slot.

PropertySheet::PerformLayout is already identified by behavior in the same
binary. Menu and PropertySheet override Panel::PerformLayout, so its current
slot is shared; no Windows/Linux destructor-slot assumption is needed.
The default short signature collides on unoptimized early builds; the existing
extended signature budget validates the already located body, never discovers it.
"""

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_common_skill,
    preprocess_vtable_via_mcp,
    write_func_yaml,
    write_vtable_yaml,
)

INHERIT_VFUNCS = [
    ("vgui2_Menu_PerformLayout", "vgui2_Menu", "GameUI_PropertySheet_PerformLayout", True),
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "vgui2_Menu_PerformLayout",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "func_sig_allow_across_function_boundary:true",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    table = await preprocess_vtable_via_mcp(
        session,
        "vgui2::Menu",
        image_base,
        platform,
        debug=debug,
        symbol_aliases=["??_7Menu@vgui2@@6B@", "_ZTVN5vgui24MenuE"],
    )
    if not table:
        return False
    table.pop("_pointer_size", None)
    write_vtable_yaml(_output_for_symbol(expected_outputs, "vgui2_Menu_vtable"), table)
    output = _output_for_symbol(expected_outputs, "vgui2_Menu_PerformLayout")
    if not await preprocess_common_skill(
        session,
        [output],
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    ):
        return False
    data = _load_yaml_mapping(output)
    data.update(func_name="vgui2::Menu::PerformLayout()", vtable_name="vgui2::Menu")
    write_func_yaml(output, data)
    return True
