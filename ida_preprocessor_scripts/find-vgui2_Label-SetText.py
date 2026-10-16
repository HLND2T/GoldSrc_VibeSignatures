#!/usr/bin/env python3
"""Find Label's wide overload through original text and hotkey receiver flow.

Use current primary RTTI and the independently verified TextImage wide slot.
Never infer Label's slot from TextImage's slot, adjacent overloads or SDK order.
"""

from ida_preprocessor_scripts._career_player_name_common import preprocess_label


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_label(session, expected_outputs, new_binary_dir, platform, image_base, debug)
