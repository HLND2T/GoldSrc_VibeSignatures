#!/usr/bin/env python3
"""Locate the Sven Co-op client ClientPortalManager::DrawPortals.

DrawPortals is the pass that actually draws the portal surfaces: it restores the
GL_ACTIVE_TEXTURE unit, enables the portal shader, walks the manager's portal
list and delegates each visible surface to DrawPortalSurface. When the texture
unit cannot be restored it reports

    "Invalid GL_ACTIVE_TEXTURE, unable to reset. Portals will not be drawn."

That sentence is the plural member of the portal diagnostic family and has
exactly one owning function per validated build (the other three sentences
belong to RenderPortals, CreateInvisiblePortalTextures and ClientPortal_CreateTexture).

Discovery is the standard exact-literal xref search: direct on Windows and on
svencoop-8948 Linux, and through a GOTOFF displacement site on svencoop-10257
Linux, where GCC PIC leaves IDA without a reference. Both paths are the shared
SvEngine fallback already used by the sibling portal finders; no byte pattern
and no LLM step participates.

DrawPortalSurface is recovered from this same function by
find-ClientPortalManager_DrawPortalSurface, and find-ClientPortalManager-shader-chain
and find-IEngineClient-view-slots consume this artifact as their predecessor.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAME = "ClientPortalManager_DrawPortals"
LITERAL = "Invalid GL_ACTIVE_TEXTURE, unable to reset. Portals will not be drawn.\n"


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
        func_name=TARGET_FUNCTION_NAME,
        literal=LITERAL,
        debug=debug,
    )
