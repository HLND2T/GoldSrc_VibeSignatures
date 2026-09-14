#!/usr/bin/env python3
"""Locate SvEngine's skybox console command through its usage literal.

The SvEngine skybox command prints ``No skybox name specified`` when invoked
without an argument and otherwise forwards Cmd_Argv(1) to the outer skybox
loader. The literal has a single instance and a single function owner on the
validated SvEngine Linux build. Serves as the Linux predecessor for
R_LoadSkyBox_SvEngine.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["SkyboxCommand"]
FUNC_XREFS = [
    {
        "func_name": "SkyboxCommand",
        "xref_strings": ["FULLMATCH:No skybox name specified\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("SkyboxCommand", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
