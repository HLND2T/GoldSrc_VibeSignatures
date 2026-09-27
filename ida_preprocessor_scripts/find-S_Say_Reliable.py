#!/usr/bin/env python3
"""Locate S_Say_Reliable by its own missing-sentence diagnostic.

``engine/snd_dma.c`` S_Say_Reliable prints
``"S_Say_Reliable: can't find sentence name %s\\n"`` when the ``spk`` argument
does not name a sentence; the sibling ``S_Say`` has its own ``"S_Say: ..."``
copy with different spelling, so this literal is owned by exactly one
function on every configured engine build.

The sibling bodies start with byte-identical prefixes on HL25 Windows and the
diagnostic's code reference is the literal entry instruction on several MSVC
builds, so the shared ``func_xrefs`` candidate path cannot carry this anchor.
The finder resolves the single owning function directly inside the worker (the
``exact_string_owner`` walk) and emits the inspected body; inspection retries
across a function boundary only where the strict unique-signature check fails.
No byte signature participates in discovery.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

FUNC_NAME = "S_Say_Reliable"
LITERAL = "S_Say_Reliable: can't find sentence name %s\n"

WALK = r"""
owner = exact_string_owner(values['literal'])
if owner is None:
    result = {'error': 'missing-sentence diagnostic has no single owning function'}
else:
    result = {'pointer_size': 4, 'owner_ea': hex(owner)}
"""


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = old_yaml_map, new_binary_dir, platform
    output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if output is None:
        return False

    located = await run_walk(session, WALK, {"literal": LITERAL})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False

    owner_ea = int(located["owner_ea"], 0)
    function = await inspect_func(session, owner_ea, image_base, FUNC_NAME)
    if function is None:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {owner_ea:#x}")
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: {FUNC_NAME}={owner_ea:#x}")
    return True
