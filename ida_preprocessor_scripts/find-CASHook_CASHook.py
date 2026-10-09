#!/usr/bin/env python3
"""Locate CASHook's constructor through its own default documentation literal.

On Sven 5.15/5.16 PE32 and ELF32, "Hook function" belongs to the constructor:
it substitutes for a null CASHookArguments documentation pointer before the
hook is linked into the registration list. C1/C2 share the ELF 5.15 body.
Output signatures are generated after discovery, never used as anchors.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CASHook_CASHook"]
FUNC_XREFS = [{"func_name": "CASHook_CASHook", "xref_strings": ["FULLMATCH:Hook function"]}]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CASHook_CASHook", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
