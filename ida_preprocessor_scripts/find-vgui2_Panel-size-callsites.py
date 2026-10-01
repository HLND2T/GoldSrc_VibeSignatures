#!/usr/bin/env python3
"""Calls to SetSize/SetMinimumSize with two constant dimensions.

One shared locator serves engine, gameui, serverbrowser and CS-family client.
Configs select Const (old HL, CoF and every Sven build) or ScaledConst (HL25).
The latter requires both unmodified results of the current Panel proportional
helper on the same receiver, each with a proven constant argument. No business
dimensions, method slots, member offsets or code addresses are finder constants.
Frame's source minimum dimensions establish a validated predecessor identity,
not a filter on the collected calls. Calls with scaled margins added to pixel
sizes, variable dimensions, mixed units and unknown provenance are not outputs.

Each final direct CALL is a patch artifact, ordered by its current binary VA.
Numbers do not imply correspondence between versions. No patch_bytes are emitted.
"""

from ida_preprocessor_scripts._panel_size_callsites_common import preprocess_size_callsites


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_size_callsites(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
