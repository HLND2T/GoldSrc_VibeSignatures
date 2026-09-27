#!/usr/bin/env python3
"""Locate the standalone CS text-color selector, excluding inline-only paths.

colorNum 3 selects GetClientColor(clientIndex), 4 returns g_LocationColor,
and all other values return NULL (cl_dll/saytext.cpp). No owned literal or
scalar float read exists. Three forms cover legacy MSVC, GCC 6153/8684,
and GCC 10210. The full return paths exclude Colorize's inlined copies.
HL25 Windows and CZDS have no confirmed standalone entry and are not registered.
Each pattern begins at the entry. The explicit-entry inspector recovers legacy
Windows entries that are absent from the warm IDB's function metadata.
"""

from ida_preprocessor_scripts._client_body_patterns import preprocess_body_patterns

SIGNATURES = {
    "GetTextColor": [
        "8B 44 24 04 83 E8 03 74 ?? 48 74 ?? 33 C0 C3 B8 ?? ?? ?? ?? C3 8B 44 24 08 50 E8 ?? ?? ?? ?? 83 C4 04 C3",
        "8B 54 24 04 8B 44 24 08 83 FA 03 74 ?? 31 C0 83 FA 04 BA ?? ?? ?? ?? 0F 44 C2 C3",
        "8B 44 24 04 8B 54 24 08 83 F8 03 74 ?? 83 F8 04 BA 00 00 00 00 B8 ?? ?? ?? ?? 0F 45 C2 C3",
    ]
}
TARGET_FUNCTION_NAMES = list(SIGNATURES)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_body_patterns(
        session, expected_outputs, SIGNATURES, image_base, debug, entry_names=TARGET_FUNCTION_NAMES
    )
