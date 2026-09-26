#!/usr/bin/env python3
"""Inherit current IEngineSurface context slots into the existing primary table."""

from ida_preprocessor_scripts._vgui_context_common import inherit_context


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await inherit_context(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        "EngineSurface",
        [
            (
                "EngineSurface_pushMakeCurrent",
                "IEngineSurface_pushMakeCurrent",
                "EngineSurface::pushMakeCurrent(int *, int *, int *, bool)",
            ),
            ("EngineSurface_popMakeCurrent", "IEngineSurface_popMakeCurrent", "EngineSurface::popMakeCurrent()"),
        ],
        debug,
    )
