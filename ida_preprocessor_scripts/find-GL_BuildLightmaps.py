#!/usr/bin/env python3
"""Locate GL_BuildLightmaps with per-branch confirmed anchors.

Three confirmed discovery branches (issue #114 batch8):

* ``hl-10210/windows``: the assertion ``surface->polys->next == NULL`` is a
  UTF-16LE literal uniquely owned by GL_BuildLightmaps, resolved through the
  shared ``xref_unicode_strings`` STRTYPE_C_16 collector.
* ``svencoop-10257/linux``: ``AllocBlock: full`` is a single-owner ASCII
  literal inside GL_BuildLightmaps' lightmap block allocator.
* every other validated branch: the covered R_NewMap body calls
  GL_BuildLightmaps directly, so a real LLM_DECOMPILE found_call against the
  annotated R_NewMap reference resolves the entry (call or tail jmp).

The branch is selected from the current gamever/platform tag; unknown tags
default to the R_NewMap chain. Addresses, byte patterns, and call ordinals are
never used for discovery; signatures are generated afterwards for validation.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill

TARGET_FUNC_NAME = "GL_BuildLightmaps"
UNICODE_BRANCH = ("hl-10210", "windows")
ASCII_BRANCH = ("svencoop-10257", "linux")

FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]

UNICODE_FUNC_XREFS = [
    {
        "func_name": TARGET_FUNC_NAME,
        "xref_strings": [],
        "xref_unicode_strings": ["FULLMATCH:surface->polys->next == NULL"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
ASCII_FUNC_XREFS = [
    {
        "func_name": TARGET_FUNC_NAME,
        "xref_strings": ["FULLMATCH:AllocBlock: full"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
R_NEWMAP_LLM_DECOMPILE = [
    {
        "symbol_name": TARGET_FUNC_NAME,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/R_NewMap.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"R_NewMap.{platform}.yaml": "required"},
    },
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    _ = skill_name, old_yaml_map
    gamever = Path(new_binary_dir).resolve().parent.name if new_binary_dir else ""
    branch = (gamever, platform)
    if branch == UNICODE_BRANCH:
        func_xrefs, llm_specs = UNICODE_FUNC_XREFS, None
    elif branch == ASCII_BRANCH:
        func_xrefs, llm_specs = ASCII_FUNC_XREFS, None
    else:
        func_xrefs, llm_specs = None, R_NEWMAP_LLM_DECOMPILE
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET_FUNC_NAME],
        func_xrefs=func_xrefs,
        llm_decompile_specs=llm_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET_FUNC_NAME, FUNC_FIELDS)],
        debug=debug,
    )
