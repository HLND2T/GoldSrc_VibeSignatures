#!/usr/bin/env python3
"""Locate the plane calculation/accumulation diagnostic owner, never GL setup.

The 8948 class retains its ELF name PortalSource; 10257 follows the repository's
recovered ClientPortal class identity. Neither is ClientPortalManager.
"""

from ida_preprocessor_scripts._sven_client_pic_common import preprocess_string_owner_skill_with_pic_fallback
from ida_analyze_util import _output_for_symbol

LITERAL = "Error: Too many clip planes on portal! Maximum: 6 (Too many surfaces on brush?)\n"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    name = (
        "PortalSource_CalculateClipPlane"
        if _output_for_symbol(expected_outputs, "PortalSource_CalculateClipPlane")
        else "ClientPortal_CalculateClipPlane"
    )
    return await preprocess_string_owner_skill_with_pic_fallback(
        session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_name=name,
        literal=LITERAL,
        debug=debug,
    )
