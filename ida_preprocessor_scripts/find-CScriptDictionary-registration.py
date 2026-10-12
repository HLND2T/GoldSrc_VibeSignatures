#!/usr/bin/env python3
"""Locate the dictionary registration predecessor through two exact literals.

dictionary@ f() and void erase(const string &in) each occur once in the four
Sven 5.15/5.16 images. Their owner intersection is unique: Windows merges
native/generic registration; Linux 5.16 preserves both but the STL erase alias
belongs only to native registration. No code/old-artifact signature discovers
the predecessor. The produced payload retains its platform's real identity.
"""

from ida_analyze_util import preprocess_common_skill
from script_dictionary_artifacts import publish_dictionary_identities

PREDECESSORS = {"windows": "RegisterScriptDictionary", "linux": "RegisterScriptDictionary_Native"}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    name = PREDECESSORS[platform]
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[name],
        func_xrefs=[
            {"func_name": name, "xref_strings": ["FULLMATCH:dictionary@ f()", "FULLMATCH:void erase(const string &in)"]}
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
        ],
        debug=debug,
    )
    return success and await publish_dictionary_identities(session, expected_outputs, platform, image_base)
