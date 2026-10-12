#!/usr/bin/env python3
"""Recover SV_ClipMoveToEntity even when ClipToLinks inlines its wrapper.

Follow callers of the validated SingleClip entry/implementation. Require the
five source arguments forwarded in order, a trace output and a returned
hidden output pointer. The seven-argument implementation additionally receives
the wrapper's passedict argument. No exported-name lookup,
fixed call ordinal, maximum function size, or previous address is a locator.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk
from ida_preprocessor_scripts._sv_clipping_common import CLIPPING_DECODER


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    names = ("SV_SingleClipMoveToEntity", "SV_SingleClipMoveToEntity_10152")
    sources = [_load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml") for name in names]
    sources = [source for source in sources if source]
    output = _output_for_symbol(expected_outputs, "SV_ClipMoveToEntity")
    if len(sources) != 1 or output is None:
        return False
    located = await run_walk(
        session,
        CLIPPING_DECODER + "\nresult = {'wrapper': hex(retained_wrapper(int(values['entry'], 0)))}",
        {"entry": sources[0]["func_va"]},
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error"):
        return False
    function = await inspect_func(session, int(located["wrapper"], 0), image_base, "SV_ClipMoveToEntity")
    if function is None:
        return False
    write_func_yaml(output, function)
    return True
