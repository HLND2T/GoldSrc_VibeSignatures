#!/usr/bin/env python3
"""Locate texture animation by its own broken-cycle diagnostic (issue #156).

Older Windows images keep two copies of the literal. All references must
collapse to one owning function; never select the first copy or call site.
"""

from ida_analyze_util import preprocess_common_skill


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["R_TextureAnimation"],
        func_xrefs=[
            {"func_name": "R_TextureAnimation", "xref_strings": ["FULLMATCH:R_TextureAnimation: broken cycle"]}
        ],
        generate_yaml_desired_fields=[
            ("R_TextureAnimation", ["func_name", "func_va", "func_rva", "func_size", "func_sig"])
        ],
        debug=debug,
    )
