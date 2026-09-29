#!/usr/bin/env python3
"""Find the Audio and Video options-page constructors from their own labels.

The page-title strings in COptionsDialog belong to the caller.  These labels
are created inside the respective constructors on every configured GameUI
build, including GCC builds whose page-title call sequence differs from MSVC.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


CONSTRUCTORS = {
    "COptionsSubAudio_ctor": ("SFX Slider", "COptionsSubAudio::COptionsSubAudio(vgui2::Panel*)"),
    "COptionsSubVideo_ctor": ("#GameUI_Brightness", "COptionsSubVideo::COptionsSubVideo(vgui2::Panel*)"),
}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if not await prepare_c_strings(session):
        return False
    names = list(CONSTRUCTORS)
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=names,
        func_xrefs=[
            {"func_name": name, "xref_strings": [f"FULLMATCH:{literal}"]} for name, (literal, _) in CONSTRUCTORS.items()
        ],
        generate_yaml_desired_fields=[
            (
                name,
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                    "func_sig_allow_across_function_boundary:true",
                ],
            )
            for name in names
        ],
        debug=debug,
    )
    if not found:
        return False
    for name, (_, real_name) in CONSTRUCTORS.items():
        output = _output_for_symbol(expected_outputs, name)
        data = _load_yaml_mapping(output)
        if data is None:
            return False
        data["func_name"] = real_name
        write_func_yaml(output, data)
    return True
