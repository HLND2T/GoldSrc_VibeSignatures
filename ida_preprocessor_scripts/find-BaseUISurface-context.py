#!/usr/bin/env python3
"""Inherit verified ISurface context slots into the existing BaseUISurface table."""

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
        "BaseUISurface",
        [
            (
                "BaseUISurface_PushMakeCurrent",
                "ISurface_PushMakeCurrent",
                "BaseUISurface::PushMakeCurrent(unsigned int, bool)",
            ),
            ("BaseUISurface_PopMakeCurrent", "ISurface_PopMakeCurrent", "BaseUISurface::PopMakeCurrent(unsigned int)"),
        ],
        debug,
    )
