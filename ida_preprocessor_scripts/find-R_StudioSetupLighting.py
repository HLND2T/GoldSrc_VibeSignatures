#!/usr/bin/env python3
"""Locate R_StudioSetupLighting and its lighting globals.

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and
common/r_studioint.h stores R_StudioSetupLighting at x86 slot 24. The
finder tries both GoldSrc/HL25/CoF and SvEngine wordings and requires one
slot VA. The body then yields r_ambientlight (int store of
alight_t.ambientlight), r_shadelight (float store of converted
alight_t.shadelight), and r_colormix (12-byte float VectorCopy of
alight_t.color after the r_icolormix AND 0xFF00 packing).
"""

from ida_preprocessor_scripts._studio_setup_common import preprocess_studio_setup_lighting


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
    _ = skill_name, old_yaml_map, new_binary_dir
    return await preprocess_studio_setup_lighting(
        session,
        expected_outputs,
        platform,
        image_base,
        debug=debug,
    )
