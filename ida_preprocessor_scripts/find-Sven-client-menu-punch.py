#!/usr/bin/env python3
"""Locate the vanilla menu dispatcher and the view-punch setter.

ShowVGUIMenu has no owned string or floating-point anchor. Its body walks
the current-menu linked list, compares the requested menu ID, and advances
to the next menu before dispatching the switch. The three patterns encode
that source loop: MSVC (both builds), GCC 8948, GCC 10257. They start at
the comparison, well after the prologue; member offsets are wildcarded.
The named 8948 ELF method confirms ShowVGUIMenu(VGUIMenu), including the
demo/intermission guards and brief/MOTD cases.

V_PunchAxis is exactly ev_punchangle[axis] = punch. Its entire short body
is a legitimate anchor; the patterns encode argument loads, indexed float
store, and return (MSVC SSE, GCC x87, GCC SSE). PIC prologues are excluded.
Discovery ignores previous artifacts and rejects the first ambiguous form.
"""

from ida_preprocessor_scripts._client_body_patterns import preprocess_body_patterns

SIGNATURES = {
    "TeamFortressViewport_ShowVGUIMenu": [
        "39 A8 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 85 C0 75 ?? 8D 45 FE 83 F8 1C",
        "3B B0 ?? ?? ?? ?? 74 ?? 8B 80 ?? ?? ?? ?? 85 C0 75 ?? 83 FE 1E",
        "3B 98 ?? ?? ?? ?? 74 ?? 8B 80 ?? ?? ?? ?? 85 C0 75 ?? 8D 53 FC 83 FA 1A",
    ],
    "V_PunchAxis": [
        "8B 44 24 04 F3 0F 10 44 24 08 F3 0F 11 04 85 ?? ?? ?? ?? C3",
        "D9 44 24 08 8B 54 24 04 D9 1C 91 C3",
        "8B 54 24 04 F3 0F 10 44 24 08 F3 0F 11 84 90 ?? ?? ?? ?? C3",
    ],
}
TARGET_FUNCTION_NAMES = list(SIGNATURES)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_body_patterns(session, expected_outputs, SIGNATURES, image_base, debug)
