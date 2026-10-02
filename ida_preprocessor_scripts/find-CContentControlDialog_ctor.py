#!/usr/bin/env python3
"""Find GameUI's content-control constructor from its own password label.

ContentControlDialog.cpp:43 constructs the PasswordReentryPrompt label using
``#GameUI_PasswordReentryPrompt``. Its exact data xref identifies the callable
constructor on nine Windows and four Linux GameUI inputs. The ELF C1/C2 aliases
share one entry and demangle to CContentControlDialog(vgui2::Panel*).

Sven 8948/10257 Windows omit this dialog, its RTTI, resource and owning options
page; those configs register this finder only for Linux. CS/CZ configs declare
no independent GameUI module. Current MSVC/GCC layouts and inlined base methods
do not change the target-owned label anchor. Signatures validate outputs only;
the shared expanded signature window distinguishes common constructor prefixes.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


TARGET = "CContentControlDialog_ctor"
REAL_NAME = "CContentControlDialog::CContentControlDialog(vgui2::Panel*)"
FUNC_XREFS = [{"func_name": TARGET, "xref_strings": ["FULLMATCH:#GameUI_PasswordReentryPrompt"]}]
GENERATE_YAML_DESIRED_FIELDS = [
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
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    output = _output_for_symbol(expected_outputs, TARGET)
    if output is None or not await prepare_c_strings(session):
        return False
    found = await preprocess_common_skill(
        session,
        expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if not found:
        return False
    data = _load_yaml_mapping(output)
    if data is None:
        return False
    data["func_name"] = REAL_NAME
    write_func_yaml(output, data)
    return True
