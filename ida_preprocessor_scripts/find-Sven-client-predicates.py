#!/usr/bin/env python3
"""Locate three Sven client predicates through their source-level operations.

The 8948 ELF names the methods TeamFortressViewport::AllowedToPrintText(),
TeamFortressViewport::IsScoreBoardVisible(), and CHud::GetBorderSize(). Their
bodies have no useful literal or distinctive floating-point coefficient set.
Each target stays within the four-signature budget across 8948/10257, PE/ELF.
Member offsets and branch distances are not discovery constants.

AllowedToPrintText rejects menu IDs 2 and 5 and permits a missing menu. The
four forms below cover MSVC branch returns (8948), MSVC setne (10257), GCC
branch/setne (8948), and GCC sete/or/inversion (10257), in that order.

GetBorderSize converts the HUD border cvar to int and clamps it to 0..100.
The four forms cover 8948 MSVC, 10257 MSVC, 8948 GCC x87, and 10257 GCC SSE.
The return tail distinguishes this method from GetWidth/GetHeight bodies
that inline the clamp and then calculate the remaining display dimension.

IsScoreBoardVisible returns false for a missing scoreboard, otherwise
tail-calls Panel::isVisible. MSVC and GCC each need one form for both builds.
The VGUI1 slot 0x28 is an independently verified ABI value: 8948 ELF's
ScorePanel address point is vtable + 8; relocation at address point + 0x28
names _ZN4vgui5Panel9isVisibleEv. All four reviewed bodies use that slot.
Wildcarding it also matches asCScriptFunction::GetObjectName (slot 0x18).
These patterns must not be reused for CS's VGUI2 implementation.

Select the first matching form and fail on ambiguity without trying a later
form. Shared x86 validation checks instruction/function ownership and emits
a fresh unique output signature; previous artifacts never drive discovery.
Require an existing decoded owner for each match. The generic xref owner's
backtracking heuristic can reject an exact entry when adjacent functions
also have callers; the explicit-owner inspector validates this entry without
reinterpreting the already verified signature as a recovery hint.
If operand wildcarding makes a short predicate's output signature ambiguous,
the standard inspector may extend that output signature across the boundary;
the discovery pattern and its owner must still be entirely inside the body.
"""

from ida_preprocessor_scripts._client_body_patterns import preprocess_body_patterns

SIGNATURES = {
    "TeamFortressViewport_AllowedToPrintText": [
        "8B 81 ?? ?? ?? ?? 85 C0 74 ?? 8B 80 ?? ?? ?? ?? 83 F8 02 74 ?? 83 F8 05 75 ?? 32 C0 C3 B0 01 C3",
        "8B 81 ?? ?? ?? ?? 85 C0 74 ?? 8B 80 ?? ?? ?? ?? 83 F8 02 74 ?? 83 F8 05 0F 95 C0 C3",
        "8B 90 ?? ?? ?? ?? 85 D2 74 ?? 8B 8A ?? ?? ?? ?? 83 F9 02 74 ?? 83 F9 05 0F 95 C0 C3",
        "8B 90 ?? ?? ?? ?? 85 D2 74 ?? 8B 8A ?? ?? ?? ?? 83 F9 02 0F 94 C0 83 F9 05 0F 94 C2 09 D0 83 F0 01 C3",
    ],
    "CHud_GetBorderSize": [
        "F3 0F 2C 40 ?? 85 C0 79 ?? 33 C0 C3 B9 64 00 00 00 3B C1 0F 4F C1 C3",
        "F3 0F 2C 50 ?? 8D 44 24 ?? 85 D2 89 54 24 ?? 0F 49 C8 83 FA 64 8D 44 24 ?? 0F 4E C1 8B 00 83 C4 ?? C3",
        "8B 04 24 83 F8 64 7E ?? B8 64 00 00 00 83 C4 ?? C3 ?? 85 C0 79 ?? 31 C0",
        "F3 0F 2C 42 ?? 83 F8 64 B9 64 00 00 00 0F 4F C1 85 C0 BA 00 00 00 00 0F 48 C2 C3",
    ],
    "TeamFortressViewport_IsScoreBoardVisible": [
        "8B 89 ?? ?? ?? ?? 85 C9 74 ?? 8B 01 8B 40 28 FF E0 32 C0 C3",
        "8B 88 ?? ?? ?? ?? 85 C9 74 ?? 8B 11 89 4C 24 04 FF 62 28 90 31 C0 C3",
    ],
}
TARGET_FUNCTION_NAMES = list(SIGNATURES)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_body_patterns(session, expected_outputs, SIGNATURES, image_base, debug)
