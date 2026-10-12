#!/usr/bin/env python3
"""Locate the frame physics dispatcher by its own invalid-movetype diagnostic.

The literal belongs to the dispatcher on GoldSrc, HL25 and SvEngine, including
decrypted BLOB inputs. No old artifact or function-header signature is a locator.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_XREFS = [{"func_name": "SV_Physics", "xref_strings": ["FULLMATCH:SV_Physics: %s bad movetype %d"]}]
GENERATE_YAML_DESIRED_FIELDS = [
    ("SV_Physics", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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
        func_names=["SV_Physics"],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
