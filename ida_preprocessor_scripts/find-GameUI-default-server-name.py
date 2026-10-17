#!/usr/bin/env python3
"""Locate HL25's Steam-persona default hostname generation, before TextEntry insertion.

The older configured GameUI binaries use settings.scr's default instead and
contain no "%s's Server" literal. Only hl-10210 declares this finder. Both
PE32 and ELF32 have one owner of that literal, also referencing hostname and
DescEdit; it is LoadGameOptionsList, not the dialog's OnOK command builder.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


SYMBOL = "CCreateMultiplayerGameGameplayPage_LoadGameOptionsList"
TARGET = "CCreateMultiplayerGameGameplayPage::LoadGameOptionsList()"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if not await prepare_c_strings(session):
        return False
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[SYMBOL],
        func_xrefs=[
            {"func_name": SYMBOL, "xref_strings": ["FULLMATCH:%s's Server", "FULLMATCH:hostname", "FULLMATCH:DescEdit"]}
        ],
        generate_yaml_desired_fields=[(SYMBOL, ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, SYMBOL)
    data = _load_yaml_mapping(output)
    if data is None:
        return False
    data["func_name"] = TARGET
    write_func_yaml(output, data)
    return True
