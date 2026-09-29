#!/usr/bin/env python3
"""Locate the condump owner for the version-specific print target.

The failure message belongs to DumpConsoleTextToFile itself, independent of
whether its Print helper was inlined by the target compiler.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


TARGET = "CGameConsoleDialog_DumpConsoleTextToFile"


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
        func_names=[TARGET],
        func_xrefs=[{"func_name": TARGET, "xref_strings": ["FULLMATCH:Unable to condump to "]}],
        generate_yaml_desired_fields=[
            (
                TARGET,
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                    "func_sig_allow_across_function_boundary:true",
                ],
            )
        ],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, TARGET)
    data = _load_yaml_mapping(output)
    if data is None:
        return False
    data["func_name"] = "CGameConsoleDialog::DumpConsoleTextToFile()"
    write_func_yaml(output, data)
    return True
