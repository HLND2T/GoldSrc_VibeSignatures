#!/usr/bin/env python3
"""Recover the startup-graphic draw call through its version-specific caller.

engine/vid_common.cpp CVideoMode_Common::DrawStartupGraphic draws the cached
startup image. Its predecessor differs by build family (issue #114 batch10):

* HL25 (hl-10210): CVideoMode_Common_PlayStartupSequence gates on ``-novid``
  and then calls DrawStartupGraphic.
* GDI builds (CoF, HL-3248..4554, Windows-only): CVideoMode_Common_Init calls
  the GDI variant (DC/compatible bitmap, BitBlt, image release).
* GL builds (HL-6153/8684, SvEngine): CVideoMode_Common_Init calls the GL
  variant (tiles/base resolution, texture upload, quad, swap, cleanup).

Each family has one explicit annotated reference body; the branch is selected
from the current gamever tag.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill

TARGET_FUNC_NAME = "CVideoMode_Common_DrawStartupGraphic"
HL25_GAMEVER = "hl-10210"
GDI_GAMEVERS = frozenset({"cof-5936", "hl-3248", "hl-3266", "hl-3329", "hl-3647", "hl-4554"})
HL25_PREDECESSOR = "CVideoMode_Common_PlayStartupSequence"
HL25_FAMILY = "hl-10210"
GDI_PREDECESSOR = "CVideoMode_Common_Init"
GDI_FAMILY = "hl-3248"
GL_PREDECESSOR = "CVideoMode_Common_Init"
GL_FAMILY = "hl-8684"

FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]


def _predecessor_reference(gamever):
    if gamever == HL25_GAMEVER:
        return HL25_PREDECESSOR, HL25_FAMILY
    if gamever in GDI_GAMEVERS:
        return GDI_PREDECESSOR, GDI_FAMILY
    return GL_PREDECESSOR, GL_FAMILY


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
    predecessor, family = _predecessor_reference(gamever)
    llm_decompile = [
        {
            "symbol_name": TARGET_FUNC_NAME,
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [
                f"references/{family}/engine/{predecessor}.{{platform}}.yaml",
            ],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {f"{predecessor}.{{platform}}.yaml": "required"},
        },
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET_FUNC_NAME],
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET_FUNC_NAME, FUNC_FIELDS)],
        debug=debug,
    )
