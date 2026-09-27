#!/usr/bin/env python3
"""Locate S_Init by its own startup banner.

``engine/snd_dma.c`` S_Init opens with ``Con_Printf("Sound Initialization\\n")``
before any cvar or command registration; that banner is the only literal the
function owns and it resolves to exactly one function on every configured
engine build (verified across the MSVC, BLOB, HL25 and SvEngine Windows
families and every GCC Linux build).

The banner is the function's first source statement, and MSVC emits the
argument ``push`` as the literal entry instruction with no prologue in front
of it. The shared ``func_xrefs`` owner recovery cannot accept an anchor that
is itself the function start, so this finder resolves the owner directly from
the single string reference inside the worker (the ``exact_string_owner``
walk) and then emits the inspected function body. No byte signature
participates in discovery.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

FUNC_NAME = "S_Init"
LITERAL = "Sound Initialization\n"

WALK = r"""
owner = exact_string_owner(values['literal'])
if owner is None:
    result = {'error': 'startup banner has no single owning function'}
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
