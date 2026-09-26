#!/usr/bin/env python3
"""Locate S_StartDynamicSound by its own pitch-zero diagnostic.

``engine/snd_dma.c`` S_StartDynamicSound prints
``"Warning: S_StartDynamicSound Ignored, called with pitch 0"`` (``Con_DPrintf``)
when a dynamic sound is requested with pitch 0.

Every MSVC and BLOB Windows build owns the literal in exactly one body, and
that body is the ABI entry. GCC Linux builds additionally keep a compiler
clone of the body (``S_StartDynamicSound.part.N`` on hl-10210 and SvEngine,
also exporting/duplicating it on the stripped svencoop builds), so the literal
can resolve to two functions, and on hl-10210 it resolves only to the big
``.part.3`` body because the thin ABI wrapper never prints it — the wrapper
tail-jumps into ``.part.3`` instead.

The ABI entry is selected structurally over candidates = literal owners plus
functions whose only transfer into an owner is a ``jmp`` (the wrapper shape),
each scored by its distinct direct-caller count, including calls routed
through a PLT stub:

- hl-10210 hw.so: wrapper 19 callers vs ``.part.3`` 6,
- svencoop-8948 hw.so: export 26 callers (PLT-routed) vs clone 4,
- svencoop-10257 hw.so: body with engine-wide callers 31 vs sound-cluster clone 5.

A tie or an empty candidate set fails closed; a single candidate is emitted
directly. No byte signature participates in discovery.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

FUNC_NAME = "S_StartDynamicSound"
LITERAL = "Warning: S_StartDynamicSound Ignored, called with pitch 0"

WALK = r"""
owners = []
literal_eas = []
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)
for item in strings:
    if str(item) == values['literal']:
        literal_eas.append(int(item.ea))
if len(literal_eas) != 1:
    result = {'error': 'pitch-zero warning must occur exactly once',
              'literals': [hex(ea) for ea in literal_eas]}
else:
    owners = set()
    for ref in idautils.XrefsTo(literal_eas[0], 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.add(int(function.start_ea))
    if not owners:
        result = {'error': 'pitch-zero warning has no owning function'}
    else:
        # A thin ABI wrapper tail-jumps into a cloned body without owning the
        # literal; include such wrappers as candidates.
        candidates = set(owners)
        for owner in owners:
            for caller, site in callers(owner):
                if caller == owner:
                    continue
                if (idc.print_insn_mnem(site) or '').lower() != 'jmp':
                    continue
                if idc.get_operand_type(site, 0) != int(idaapi.o_near):
                    continue
                if int(idc.get_operand_value(site, 0)) == owner:
                    candidates.add(caller)
        counts = {}
        for candidate in candidates:
            counts[candidate] = len(callers(candidate))
        if len(candidates) == 1:
            target = next(iter(candidates))
            result = {'pointer_size': 4, 'mode': 'single', 'target': hex(target),
                      'candidates': {hex(target): counts[target]}}
        else:
            best = max(counts.values())
            winners = [c for c, count in counts.items() if count == best]
            if len(winners) != 1 or best == 0:
                result = {'error': 'ABI entry is ambiguous among cloned bodies',
                          'candidates': {hex(c): n for c, n in counts.items()}}
            else:
                target = winners[0]
                result = {'pointer_size': 4, 'mode': 'callers', 'target': hex(target),
                          'candidates': {hex(c): n for c, n in counts.items()}}
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

    target = int(located["target"], 0)
    function = await inspect_func(session, target, image_base, FUNC_NAME)
    if function is None:
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: {FUNC_NAME}={target:#x} mode={located['mode']}")
    return True
