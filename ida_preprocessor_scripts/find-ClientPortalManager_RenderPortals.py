#!/usr/bin/env python3
"""Locate the Sven Co-op client ClientPortalManager::RenderPortals.

svencoop 5.2x's portal manager renders every active portal; when the
GL_ACTIVE_TEXTURE unit cannot be restored it reports
"Invalid GL_ACTIVE_TEXTURE, unable to reset. Portal not drawn." and skips the
portal draw. That diagnostic has exactly one function owner on the validated
10257 client: a direct literal owner on Windows, and on Linux a single
GOTOFF displacement site resolved through the SvEngine PIC fallback in
_sven_client_pic_common (svencoop-10257 only).

RenderPortals renders each portal's view into its texture. The sibling pass
ClientPortalManager::DrawPortals, which draws the portal surfaces themselves,
owns a different diagnostic ("Portals will not be drawn.") and is the
predecessor of find-ClientPortalManager_DrawPortalSurface; neither
DrawPortalSurface nor GetOriginalSurfaceTexture is reachable from here.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAMES = ["ClientPortalManager_RenderPortals"]
LITERAL = "Invalid GL_ACTIVE_TEXTURE, unable to reset. Portal not drawn.\n"


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
    return await preprocess_string_owner_skill_with_pic_fallback(
        session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_name=TARGET_FUNCTION_NAMES[0],
        literal=LITERAL,
        debug=debug,
    )
