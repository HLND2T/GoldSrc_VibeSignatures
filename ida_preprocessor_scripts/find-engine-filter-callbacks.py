#!/usr/bin/env python3
"""Resolve SDK cl_enginefuncs slots 108..110, approved in issue #152.

APIProxy.h declares Mode, Color and Brightness in that order (four-byte slots).
All 15 engine inputs were checked against the actual argument-to-store flow.
SvEngine's corresponding ELF symbols are SetFilter*_I; these entries already
contain the stores, unlike the forwarding drawing callbacks. Globals are mined
separately with found_gv, including the Linux PIC/GOT accesses.
"""

from pathlib import Path

from ida_preprocessor_scripts._engine_public_callback_common import preprocess_engine_callback

CALLBACK_SLOTS = {"SetFilterMode": 108, "SetFilterColor": 109, "SetFilterBrightness": 110}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, debug
    for callback, slot in CALLBACK_SLOTS.items():
        names = [
            name
            for name in (callback, callback + "_I")
            if any(Path(output).name == f"{name}.{platform}.yaml" for output in expected_outputs)
        ]
        if len(names) != 1:
            return False
        if not await preprocess_engine_callback(
            session, expected_outputs, new_binary_dir, platform, image_base, name=names[0], slot=slot
        ):
            return False
    return True
