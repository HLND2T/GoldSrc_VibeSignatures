#!/usr/bin/env python3
"""Locate the active console path's CR filter branch, including inline variants.

The decoded comparison must consume the verified scalar/string argument, and
its non-CR successor must exclusively update line-break count minus two and
repaint. Source-derived control flow replaces instruction windows and call
ordinals. Emit the branch locator only; this finder never patches input bytes.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._gameui_richtext_common import CHAR, CHECK, PATCH, WIDE
from ida_preprocessor_scripts._patch_signature_common import run_signature
from ida_preprocessor_scripts._vgui_paint_common import walk


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    wide = platform == "linux" or Path(new_binary_dir).parent.name == "hl-10210"
    stem = WIDE if wide else CHAR
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"{stem}.{platform}.yaml")
    output = _output_for_symbol(expected_outputs, PATCH)
    if owner is None or output is None:
        return False
    try:
        address = int(str(owner["func_va"]), 0)
    except (KeyError, TypeError, ValueError):
        return False
    checked = await walk(session, CHECK, dict(target=address, platform=platform, kind="patch", wide=wide))
    if checked.get("error") or not isinstance(checked.get("branch"), int):
        if debug:
            print(f"  RichText CR branch validation failed: {checked}")
        return False
    branch = checked["branch"]
    signature = await run_signature(session, branch)
    if signature is None:
        return False
    write_patch_yaml(
        output,
        dict(
            patch_name="vgui2::RichText carriage-return filter branch",
            patch_va=hex(branch),
            patch_rva=hex(branch - image_base),
            **signature,
        ),
    )
    return True
