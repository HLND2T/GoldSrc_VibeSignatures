#!/usr/bin/env python3
"""GameUI SetBounds calls whose four explicit arguments have constant provenance.

Recover SetPos/SetSize interface identities from the current Panel::Init and
validate SetBounds as their exact four-argument forwarder (including inlined
IPanel dispatches). No fixed method address, slot or business dimensions locate
the collected calls. Outputs mark actual direct CALL instructions, without
replacement bytes; numbering is local to each binary.

Const requires four direct constants. ScaledConst requires unmodified results
of the current proportional helper on the final Panel receiver, with literal
zero also permitted for x/y. Unlike the SetSize finder, HL25 retains both modes.
Unproven stack cleanup invalidates only downstream calls whose provenance may
be affected; it never converts unknown parameters into a constant match.
"""

from ida_preprocessor_scripts._panel_bounds_callsites_common import preprocess_bounds_callsites


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_bounds_callsites(
        session, expected_outputs, new_binary_dir, platform, image_base, debug=debug
    )
