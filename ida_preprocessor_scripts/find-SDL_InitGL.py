#!/usr/bin/env python3
"""Locate SDL_InitGL through its glAccum procedure-name literal.

SDL_InitGL (MetaHook name; Linux debug name QGL_Init, engine/qgl.c) is the
engine-private wrapper that bulk-resolves GL procedure addresses through
SDL_GL_GetProcAddress; the exact ``glAccum`` name (no newline) resolves one
procedure slot and belongs to this wrapper only. The ``glAccum\n`` variant
belongs to a logging wrapper and must not be used.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["SDL_InitGL"]
FUNC_XREFS = [
    {
        "func_name": "SDL_InitGL",
        "xref_strings": ["FULLMATCH:glAccum"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("SDL_InitGL", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
