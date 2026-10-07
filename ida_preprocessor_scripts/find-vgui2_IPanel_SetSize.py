#!/usr/bin/env python3
"""Recover the IPanel::SetSize slot from the current GameUI Panel identities.

Panel::Init forwards its third/fourth explicit parameters to IPanel::SetSize,
and the unique standalone Panel::SetSize wrapper forwards its own two explicit
arguments to the same interface slot. The constant-size callsite finder already
proves both facts; reuse that identity instead of a fixed ABI slot. Windows
and Linux slots differ.
"""

import inspect
from pathlib import Path

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._panel_size_callsites_common import IDENTITY_SOURCE
from ida_preprocessor_scripts._panel_size_collect import IDENTIFY
from ida_preprocessor_scripts._vgui_paint_common import walk, write_slot
from ida_preprocessor_scripts._vgui_private_method_identity import stack_check_preserves_registers


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, image_base
    record = _load_yaml_mapping(Path(new_binary_dir) / f"vgui2_Panel_Init.{platform}.yaml")
    if not record or record.get("func_name") != "vgui2::Panel::Init(int, int, int, int)":
        return False
    source = inspect.getsource(stack_check_preserves_registers) + "\n" + IDENTITY_SOURCE + "\n" + IDENTIFY
    found = await walk(session, source, dict(platform=platform, init=int(record["func_va"], 0), scaled=False))
    if found.get("error") or len(found.get("methods", {}).get("SetSize", [])) != 1:
        if debug:
            print(found)
        return False
    return write_slot(expected_outputs, "vgui2_IPanel_SetSize", "vgui2::IPanel", "SetSize", found["slots"][0])
