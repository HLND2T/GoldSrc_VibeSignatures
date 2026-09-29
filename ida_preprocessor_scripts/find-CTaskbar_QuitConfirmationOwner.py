#!/usr/bin/env python3
"""Find the body that creates the quit-confirmation QueryBox.

The exact quit-title token has one owning function in each GameUI binary.
Older builds keep OnOpenQuitConfirmationDialog out of line; HL25/SvEngine
Windows can inline it into OnCommand. This internal artifact therefore names
the containing body, not a fixed source function.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


OWNER = "CTaskbar_QuitConfirmationOwner"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if not await prepare_c_strings(session):
        return False
    return await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[OWNER],
        func_xrefs=[{"func_name": OWNER, "xref_strings": ["FULLMATCH:#GameUI_QuitConfirmationTitle"]}],
        generate_yaml_desired_fields=[(OWNER, ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
