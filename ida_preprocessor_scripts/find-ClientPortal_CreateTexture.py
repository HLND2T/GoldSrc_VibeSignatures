"""Linux portal texture initializer; inlined into RenderPortals on Windows."""

from ida_preprocessor_scripts._sven_client_pic_common import preprocess_string_owner_skill_with_pic_fallback
from ida_analyze_util import _output_for_symbol


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    if platform != "linux":
        return False
    return await preprocess_string_owner_skill_with_pic_fallback(
        session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_name="PortalSource_CreateTexture"
        if _output_for_symbol(expected_outputs, "PortalSource_CreateTexture")
        else "ClientPortal_CreateTexture",
        literal="Invalid GL_ACTIVE_TEXTURE, unable to reset. Couldn't create texture for PortalSource.\n",
        debug=debug,
    )
