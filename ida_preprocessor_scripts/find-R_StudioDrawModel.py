#!/usr/bin/env python3
"""Locate R_StudioDrawModel (GoldSrc/HL25/CoF families).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &pStudioAPI to the client studio interface, and the global's
static initializer is the r_studio_interface_t studio object
{STUDIO_INTERFACE_VERSION, R_StudioDrawModel, R_StudioDrawPlayer}. The +8
slot must equal the verified R_StudioDrawPlayer artifact (DAG input), which
anchors the interface identity so the +4 slot is R_StudioDrawModel
(validated 2026-09-10: hl-10210 hw.dll studio+4 0x101F35E0 / +8 0x101F0580,
hl-10210 hw.so 0xD28E0/0xD28B0, hl-8684 0x1D84AF0/0x1D853B0, hl-3248
0x1D8E5C0/0x1D8EED0, svencoop-10257 hw.dll 0x1D90580/0x1D8A390, cof-5936
0x1DBE9EF/0x1DBF4F1). The source's dead-player branch calls
R_StudioDrawPlayer directly from R_StudioDrawModel; that call edge exists on
every Windows build and is logged as corroboration, while GCC Linux keeps
it inside a .part.N cold clone. SvEngine ships a different diagnostic
wording and is covered by find-R_StudioDrawModel-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    preprocess_studio_draw_model,
)

TARGET_NAME = "R_StudioDrawModel"


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
    return await preprocess_studio_draw_model(
        session,
        expected_outputs,
        platform,
        image_base,
        target_name=TARGET_NAME,
        studio_string=HL_STUDIO_STRING,
        new_binary_dir=new_binary_dir,
        debug=debug,
    )
