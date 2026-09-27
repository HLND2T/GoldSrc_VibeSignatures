#!/usr/bin/env python3
"""Locate HL25 CS/CZ Colorize through its inlined text-color selection.

The 3/4/NULL selection plus passing m_clientIndex to GetClientColor uniquely
identifies the true Colorize owner in both Windows 10210 clients. Displacements
for branches, member layout, data and callee are wildcarded. Shared UtlVector
assertions are not unique owner anchors. Never emit this block as GetTextColor.
"""

from ida_preprocessor_scripts._client_body_patterns import preprocess_body_patterns

SIGNATURES = {
    "SayTextLine_Colorize": [
        "83 E9 03 74 ?? 83 E9 01 74 ?? 33 C0 EB ?? B8 ?? ?? ?? ?? EB ?? FF B6 ?? ?? ?? ?? E8 ?? ?? ?? ??"
    ]
}
TARGET_FUNCTION_NAMES = list(SIGNATURES)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_body_patterns(session, expected_outputs, SIGNATURES, image_base, debug)
