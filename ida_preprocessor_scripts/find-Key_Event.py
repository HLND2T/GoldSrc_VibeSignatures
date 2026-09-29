#!/usr/bin/env python3
"""Locate Key_Event through its target-owned unbound-key diagnostic.

engine/keys.c prints "%s is unbound.\n" when a pressed key has no binding.
The exact literal has one owning function on all 15 configured engine/platform
pairs, including decrypted BLOBs. The alternative "ctrl-alt-del pressed" is
absent on both Sven versions, so it must not constrain discovery. ELF symbols
confirm Key_Event is a free function, distinct from CEngine::TrapKey_Event.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Key_Event"]
FUNC_XREFS = [
    {
        "func_name": "Key_Event",
        "xref_strings": ["FULLMATCH:%s is unbound.\n"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Key_Event", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
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
