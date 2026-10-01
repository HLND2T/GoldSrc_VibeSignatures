#!/usr/bin/env python3
"""Recover Menu's scrolling method and ScrollBar pointer from PerformLayout.

The scrolling branch adds the scrollbar and invokes MakeItemsVisibleInScrollRange
on the Menu receiver. LayoutMenuBorder follows both branches and corroborates
their role. The scroller is the member receiver of visibility/range/window
operations, not a menu-item pointer or the embedded item containers.
The target ABI has MakeItemsVisibleInScrollRange(), unlike the newer SDK's
two-argument overload. References retain this binary/source difference.

Source: HLND2T_official/vgui2/controls/Menu.cpp, PerformLayout (473),
MakeItemsVisibleInScrollRange (713), LayoutMenuBorder (751). All configured
GameUI binaries are covered; CS-family configs reuse the Half-Life module.
"""

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    preprocess_common_skill,
    write_func_yaml,
    write_struct_offset_yaml,
)

LLM_DECOMPILE = [
    {
        "symbol_name": "vgui2_Menu_MakeItemsVisibleInScrollRange",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/gameui/vgui2_Menu_PerformLayout.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"vgui2_Menu_PerformLayout.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "vgui2_Menu_m_pScroller",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/gameui/vgui2_Menu_PerformLayout.{platform}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {"vgui2_Menu_PerformLayout.{platform}.yaml": "required"},
        "expected_size": 4,
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "vgui2_Menu_MakeItemsVisibleInScrollRange",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vfunc_sig",
            "vfunc_sig_allow_across_function_boundary:true",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "vgui2_Menu_m_pScroller",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
            "offset_sig_allow_across_function_boundary:true",
        ],
    ),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["vgui2_Menu_MakeItemsVisibleInScrollRange"],
        func_vtable_relations=[("vgui2_Menu_MakeItemsVisibleInScrollRange", "vgui2_Menu")],
        struct_member_names=["vgui2_Menu_m_pScroller"],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, "vgui2_Menu_MakeItemsVisibleInScrollRange")
    data = _load_yaml_mapping(output)
    data.update(func_name="vgui2::Menu::MakeItemsVisibleInScrollRange()", vtable_name="vgui2::Menu")
    write_func_yaml(output, data)
    output = _output_for_symbol(expected_outputs, "vgui2_Menu_m_pScroller")
    data = _load_yaml_mapping(output)
    data.update(struct_name="vgui2::Menu", member_name="m_pScroller")
    write_struct_offset_yaml(output, data)
    return True
