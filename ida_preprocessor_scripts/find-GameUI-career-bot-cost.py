#!/usr/bin/env python3
"""Recover Career's complete character setter, integer cost getter and text array.

Anchor the exact #Career_Cost owner and corroborate BotPointsFont/BotNameFont
and EmptyChar. Recover GetPoints from the modulo-ten ASCII expression, checking
the machine CALL and character-parameter receiver. Follow the wide TextImage
dispatch to its current this-relative array base, then verify the encoded
member operand. Empty-character constprop bodies cannot satisfy the anchor.

Short getters can require output signatures across the function boundary; the
actual discovery invariant remains the setter's cost-conversion CALL, never
the getter's prologue or a prior artifact's bytes.
"""

from ida_preprocessor_scripts._career_bot_cost_common import preprocess_career


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_career(session, expected_outputs, new_binary_dir, platform, image_base, debug)
