#!/usr/bin/env python3
"""Locate Part E predecessors through exact, target-owned literals.

The string registration owns both the string opAssign and destructor declarations.
The module-builder constructor owns its null-module-info diagnostic. Each literal
has one occurrence/owner on Sven 5.15/5.16 PE32/ELF32. Caller-owned SERVER does not
directly identify DefineWord. No byte pattern, symbol name or old artifact locates
these predecessors; signatures are generated only after string-xref discovery.
"""

from cstring_builder_artifacts import publish_identities
from ida_analyze_util import preprocess_common_skill

FUNC_XREFS = [
    {
        "func_name": "RegisterSCScriptASString",
        "xref_strings": [
            "FULLMATCH:void Destructstring()",
            "FULLMATCH:string& opAssign(const string& in szString)",
        ],
    },
    {
        "func_name": "CASModuleBuilder_CASModuleBuilder",
        "xref_strings": ["FULLMATCH:CASModuleBuilder::CASModuleBuilder: null module info!\n"],
    },
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    targets = [spec["func_name"] for spec in FUNC_XREFS]
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        func_xrefs=FUNC_XREFS,
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
            for name in targets
        ],
        debug=debug,
    )
    return success and await publish_identities(session, expected_outputs, platform, image_base)
