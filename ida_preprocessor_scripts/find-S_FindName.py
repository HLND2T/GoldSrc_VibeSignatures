#!/usr/bin/env python3
"""Locate S_FindName through its NULL-name guard and the VOX_LoadSound caller.

``engine/snd_dma.c`` S_FindName opens with
``Sys_Error("S_FindName: NULL\\n")`` when called without a name. On every MSVC
and BLOB Windows build and on hl-10210 Linux that literal resolves to exactly
one function. GCC Linux builds can additionally keep a ``pfInCache == NULL``
specialization (``S_FindName.constprop.N`` on hl-8684, called by
S_PrecacheSound / S_TouchSound / S_Say_Reliable with a NULL out-parameter),
duplicating the guard; the generic body is the one ``VOX_LoadSound`` calls
(``engine/snd_mix.c`` passes ``&rgvoxword[cword].fKeepCached``).

The finder therefore collects the guard's owning functions and selects the one
that is a direct callee of the already-produced ``VOX_LoadSound`` artifact
(PLT stubs resolved). Multiple or zero callees among the owners, or a single
owner when VOX_LoadSound calls none of them, fail closed; a single owner that
VOX_LoadSound calls is emitted directly. No byte signature participates in
discovery.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

FUNC_NAME = "S_FindName"
VOX_NAME = "VOX_LoadSound"
LITERAL = "S_FindName: NULL\n"

WALK = r"""
vox = int(values['vox'], 0)
literals = []
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)
for item in strings:
    if str(item) == values['literal']:
        literals.append(int(item.ea))
if len(literals) != 1:
    result = {'error': 'S_FindName guard literal must occur exactly once',
              'literals': [hex(ea) for ea in literals]}
else:
    owners = set()
    for ref in idautils.XrefsTo(literals[0], 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.add(int(function.start_ea))
    if not owners:
        result = {'error': 'S_FindName guard has no owning function'}
    elif len(owners) == 1:
        owner = next(iter(owners))
        result = {'pointer_size': 4, 'mode': 'single', 'target': hex(owner),
                  'owners': [hex(owner)], 'vox_callees': []}
    else:
        callees = sorted(set(owners) & set(direct_calls(vox)))
        if len(callees) != 1:
            result = {'error': 'VOX_LoadSound must call exactly one guard owner',
                      'owners': [hex(o) for o in sorted(owners)],
                      'vox_callees': [hex(c) for c in callees]}
        else:
            result = {'pointer_size': 4, 'mode': 'vox_callee', 'target': hex(callees[0]),
                      'owners': [hex(o) for o in sorted(owners)],
                      'vox_callees': [hex(c) for c in callees]}
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
    _ = old_yaml_map, platform
    output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if output is None:
        return False

    vox = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, VOX_NAME)
    if vox is None:
        if debug:
            print(f"{skill_name}: missing or invalid {VOX_NAME} artifact")
        return False

    located = await run_walk(session, WALK, {"literal": LITERAL, "vox": hex(vox["owner_ea"])})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False

    target = int(located["target"], 0)
    function = await inspect_func(session, target, image_base, FUNC_NAME)
    if function is None:
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: {FUNC_NAME}={target:#x} mode={located['mode']}")
    return True
