#!/usr/bin/env python3
"""Recover ComboBox/Label methods from BuildModeDialog and current RTTI tables.

Anchor: exact autoresize + localize literals. Menu's four-argument AddMenuItem
consumes the original userData, ComboBox receiver and SetText/text message.
The wide overload passes a converted local buffer to that same menu method,
retaining the original wide text in the message. GetMenu returns the derived
dropdown member. No SDK slot order, version-specific offset or old signature
participates in discovery. Short getter signatures may extend past the body.
"""

from ida_preprocessor_scripts._combobox_unicode_common import preprocess_combo


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_combo(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
