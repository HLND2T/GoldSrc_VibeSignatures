#!/usr/bin/env python3
"""Locate CL_IsDevOverviewMode from the scene renderer it gates.

``engine/gl_rmain.c`` opens the scene renderer with

    if ( CL_IsDevOverviewMode() )
        CL_SetDevOverView( &r_refdef );

so ``CL_IsDevOverviewMode`` is the nearest call before a ``CL_SetDevOverView``
call site. The call may sit in the same basic block (CoF, SvEngine Windows) or
in the guard block that branches into the setter block (HL25 Linux), so the
search walks backwards across single-predecessor blocks. The renderer itself is
derived, never named: SvEngine 10257 Windows inlines ``R_RenderScene`` into
``R_RenderView``, and the older builds put unrelated calls first, so neither the
function name nor "the first call" is a valid anchor.

The candidate must stay small and call at most one helper (SvEngine resolves the
cvar through a getter), which separates it from
``CL_CalculateDevOverviewParameters``.
Discovery never consumes an old artifact signature.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, _parse_int, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    owner_context,
    run_walk,
)

FUNC_NAME = "CL_IsDevOverviewMode"
OWNER_FUNC_NAME = "CL_SetDevOverView"
MAX_BLOCK_HOPS = 6
# CL_IsDevOverviewMode is a tiny predicate; CL_CalculateDevOverviewParameters is far larger.
MAX_SIZE = 0x80
MAX_CALLS = 1

WALK = r"""
SETDEV = int(values['setdev'], 0)
HOPS = int(values['hops'])
MAX_SIZE = int(values['max_size'])
MAX_CALLS = int(values['max_calls'])


# Direct call target, unwrapping a PIC PLT stub when the linker routed it there.
def call_target(site):
    if idc.get_operand_type(site, 0) != int(idaapi.o_near):
        return None
    target = resolve_elf_plt(int(idc.get_operand_value(site, 0)))
    function = ida_funcs.get_func(target)
    return target if function is not None and int(function.start_ea) == target else None


def preceding_call(func, site, blocks, predecessors):
    # Nearest call before ``site``, crossing single-predecessor block edges.
    block = None
    for candidate in blocks:
        if candidate.start_ea <= site < candidate.end_ea:
            block = candidate
            break
    for _ in range(HOPS):
        if block is None:
            return None
        for head in reversed([head for head in idautils.Heads(block.start_ea, block.end_ea) if head < site]):
            if (idc.print_insn_mnem(head) or '').lower() == 'call':
                return call_target(head)
        incoming = predecessors.get(block.start_ea, [])
        if len(incoming) != 1:
            return None
        block = incoming[0]
        site = block.end_ea
    return None


renderers = sorted({start for start, _ in callers(SETDEV)})
if len(renderers) != 1:
    result = {'error': 'CL_SetDevOverView caller is not unique: %s' % [hex(x) for x in renderers]}
else:
    renderer = renderers[0]
    renderer_entries = scan(renderer)
    if renderer_entries is None:
        result = {'error': 'scene renderer is not a function start'}
    else:
        import ida_gdl
        owner = ida_funcs.get_func(renderer)
        blocks = list(ida_gdl.FlowChart(owner))
        predecessors = {}
        for block in blocks:
            for successor in block.succs():
                predecessors.setdefault(successor.start_ea, []).append(block)
        sites = sorted(site for start, site in callers(SETDEV) if start == renderer)
        candidates = []
        for site in sites:
            preceding = preceding_call(owner, site, blocks, predecessors)
            if preceding is None:
                candidates.append({'site': hex(site), 'callee': None})
                continue
            entries = scan(preceding)
            if entries is None:
                candidates.append({'site': hex(site), 'callee': hex(preceding), 'reason': 'not a function'})
                continue
            calls = [entry for entry in entries if entry['mnem'] == 'call']
            size = int(ida_funcs.get_func(preceding).end_ea) - preceding
            if size > MAX_SIZE or len(calls) > MAX_CALLS:
                candidates.append({'site': hex(site), 'callee': hex(preceding),
                                   'size': hex(size), 'calls': len(calls),
                                   'reason': 'too large or too many calls'})
                continue
            candidates.append({
                'site': hex(site),
                'callee': hex(preceding),
                'calls': len(calls),
                'size': hex(size),
            })
        chosen = {entry['callee'] for entry in candidates if entry.get('calls') is not None}
        if len(chosen) != 1:
            result = {'error': 'CL_IsDevOverviewMode candidate is not unique',
                      'renderer': hex(renderer), 'candidates': candidates}
        else:
            result = {
                'pointer_size': 4,
                'renderer': hex(renderer),
                'func_ea': int(next(iter(chosen)), 0),
                'sites': candidates,
            }
"""


def _func_ea(new_binary_dir, platform, name, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != name:
        return None
    try:
        func_ea = _parse_int(artifact["func_va"], "func_va")
    except Exception:  # noqa: BLE001 - malformed artifact fails closed.
        return None
    return func_ea if func_ea >= int(image_base) else None


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
    _ = skill_name, old_yaml_map
    output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if output is None:
        return False
    setdev_ea = _func_ea(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if setdev_ea is None:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} artifact")
        return False
    located = await run_walk(
        session, WALK, {"setdev": hex(setdev_ea), "hops": MAX_BLOCK_HOPS, "max_size": MAX_SIZE, "max_calls": MAX_CALLS}
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located}")
        return False
    renderer = int(located["renderer"], 0)
    owner = await owner_context(session, renderer, image_base, "R_RenderScene")
    if owner is None:
        if debug:
            print(f"{skill_name}: could not revalidate the scene renderer at {renderer:#x}")
        return False
    function = await inspect_func(session, int(located["func_ea"]), image_base, FUNC_NAME)
    if not function:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {located['func_ea']}")
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: renderer={renderer:#x} {FUNC_NAME}={located['func_ea']} size={function['func_size']}")
    return True
