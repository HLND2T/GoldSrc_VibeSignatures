#!/usr/bin/env python3
"""Recover CS/CZ spectator's wide ComboBox calls from current control flow.

Anchor: exact #Spec_PlayerItem_Team + UserData literals. The no-team string is
optimized away in CZDS 8684 Linux. Windows may put PlayerAddItem out of line;
GCC may split the implementation into a clone with a register-only ABI. Emit
the original virtual entry separately from that implementation. Each ComboBox
address comes from the current client table, never another module's table.
"""

from ida_preprocessor_scripts._combobox_unicode_common import preprocess_combo


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_combo(
        session, expected_outputs, new_binary_dir, platform, image_base, client=True, debug=debug
    )
