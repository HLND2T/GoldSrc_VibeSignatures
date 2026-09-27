#!/usr/bin/env python3
"""Locate CS/CZ/CZDS GetClientColor through the verified team-color selector.

The four forms cover legacy MSVC CS, HL25 MSVC CS, both MSVC CZDS builds,
and all three GCC CS clients, respectively. They encode the 16-bit team read
and switch (MSVC), or the normalized 16-bit index into the color pointer table
(GCC). Returned arrays are addresses, not scalar reads usable by xref_floats.

CS returns Red/Blue/Yellow/Green for 1..4 and Grey otherwise; public source's
team-0 Yellow case does not match these binaries. CZDS instead selects from
0..4 without subtracting one. Player strides (104/116/28) are deliberately
absent from discovery. The first return distinguishes out-of-line MSVC CS
from inlined copies. The CZDS form is unique in both applicable modules.
"""

from ida_preprocessor_scripts._client_body_patterns import preprocess_body_patterns

SIGNATURES = {
    "GetClientColor": [
        "0F BF 04 ?? ?? ?? ?? ?? 48 83 F8 03 77 ?? FF 24 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? C3",
        "0F BF 80 ?? ?? ?? ?? 48 83 F8 03 77 ?? FF 24 85 ?? ?? ?? ?? B8 ?? ?? ?? ?? 5D C3",
        "0F BF 04 8D ?? ?? ?? ?? 83 F8 04 77 ?? FF 24 85 ?? ?? ?? ?? B8 ?? ?? ?? ??",
        "B8 ?? ?? ?? ?? 4A 0F B7 D2 83 FA 03 77 ?? 8B 04 95 ?? ?? ?? ?? C3",
    ]
}
TARGET_FUNCTION_NAMES = list(SIGNATURES)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_body_patterns(session, expected_outputs, SIGNATURES, image_base, debug)
