#!/usr/bin/env python3
"""Find three GameUI constructors through literals in their own bodies.

ConsoleSubmit names the console's submit button; CSBotConfig names the
multiplayer dialog's KeyValues object; #GameUI_Keyboard labels an options
page. Their exact data xrefs each identify one constructor on the configured
PE32/ELF32 builds. The title literals in MetaHookSv are unsuitable on Linux:
the compiler can move SetTitle into a specialized helper.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


CONSTRUCTORS = {
    "CGameConsoleDialog_ctor": (
        "ConsoleSubmit",
        "CGameConsoleDialog::CGameConsoleDialog()",
    ),
    "CCreateMultiplayerGameDialog_ctor": (
        "CSBotConfig",
        "CCreateMultiplayerGameDialog::CCreateMultiplayerGameDialog(vgui2::Panel*)",
    ),
    "COptionsDialog_ctor": (
        "#GameUI_Keyboard",
        "COptionsDialog::COptionsDialog(vgui2::Panel*)",
    ),
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
            {"func_name": name, "xref_strings": [f"FULLMATCH:{anchor}"]} for name, (anchor, _) in CONSTRUCTORS.items()
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
