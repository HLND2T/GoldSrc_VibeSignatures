#!/usr/bin/env python3
"""Recover the sentence-lookup symbols from VOX_LoadSound's lookup code.

``VOX_LoadSound`` resolves its sentence name through ``VOX_LookupString``
(``snd_mix.c``). That lookup begins with ``pszin[0] == '#'``: the equal branch
passes ``atoi(pszin + 1)`` to ``SequenceGetSentenceByIndex``; the other branch
loops ``i < cszrawsentences`` comparing against ``rgpszrawsentence[i]``.

Old Windows builds keep ``VOX_LookupString`` as the unique direct callee with
that ``'#'`` compare. Newer MSVC and every GCC build inline it into
``VOX_LoadSound``, which then owns the only compare itself. GCC additionally
emits an uncalled external copy; it is not a lookup ``VOX_LoadSound`` uses, so
``VOX_LookupString`` is emitted only when it is the real standalone callee.

From the ``'#'`` compare the walk takes the second call on the straight-line
equal branch (after atoi/strtol) as ``SequenceGetSentenceByIndex`` and verifies
its sentence-group list walk (``+4`` count, ``+8`` first sentence, ``+0xC``
next group). The first global read on the not-equal branch is
``cszrawsentences``; the one loop re-reading it, with its entry blocks, touches
exactly one other global, ``rgpszrawsentence``, which must also be indexed as
``[reg*4]``. Calls resolve through ELF PLT stubs and PIC globals through the
shared GOT decoder. Any other shape fails closed.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import func_payload, inspect_func, owner_context, run_walk

OWNER_NAME = "VOX_LoadSound"
LOOKUP_NAME = "VOX_LookupString"
SEQUENCE_NAME = "SequenceGetSentenceByIndex"
COUNT_NAME = "cszrawsentences"
ARRAY_NAME = "rgpszrawsentence"
REQUIRED_NAMES = (SEQUENCE_NAME, COUNT_NAME, ARRAY_NAME)

WALK = r"""
import ida_gdl

OWNER = int(values['owner'], 0)
HASH = ord('#')
MAX_TRACE = 32
# sentenceGroupEntry_s: numSentences, firstSentence, nextEntry.
GROUP_OFFSETS = (4, 8, 12)


def width(op):
    return int(ida_ua.get_dtype_size(op.dtype))


def is_byte_memory(op):
    return int(op.type) in (int(idaapi.o_phrase), int(idaapi.o_displ)) and width(op) == 1


# Compares of pszin[0] against '#', directly or through a movsx/movzx register.
def hash_compares(start):
    items = list(idautils.FuncItems(int(start)))
    sites = []
    for index, ea in enumerate(items):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn or (idc.print_insn_mnem(int(ea)) or '').lower() != 'cmp':
            continue
        source = insn.ops[1]
        if int(source.type) != int(idaapi.o_imm) or int(source.value) != HASH:
            continue
        destination = insn.ops[0]
        if is_byte_memory(destination):
            sites.append(int(ea))
            continue
        if int(destination.type) != int(idaapi.o_reg) or index == 0:
            continue
        previous = idautils.DecodeInstruction(int(items[index - 1]))
        mnemonic = (idc.print_insn_mnem(int(items[index - 1])) or '').lower()
        if (previous and mnemonic in ('movsx', 'movzx')
                and int(previous.ops[0].type) == int(idaapi.o_reg)
                and reg4(previous.ops[0]) == reg4(destination)
                and is_byte_memory(previous.ops[1])):
            sites.append(int(ea))
    return sites


# (equal target, not-equal target) of the conditional jump after the compare.
def hash_branches(site):
    jump = int(idc.next_head(int(site), idaapi.BADADDR))
    mnemonic = (idc.print_insn_mnem(jump) or '').lower()
    if mnemonic not in ('jz', 'je', 'jnz', 'jne'):
        return None
    taken = int(idc.get_operand_value(jump, 0))
    following = int(idc.next_head(jump, idaapi.BADADDR))
    return (taken, following) if mnemonic in ('jz', 'je') else (following, taken)


# Straight-line path from start, following unconditional jumps, to the next branch.
def straight_line(start, owner):
    function = ida_funcs.get_func(int(owner))
    path = []
    ea = int(start)
    while len(path) < MAX_TRACE and int(function.start_ea) <= ea < int(function.end_ea):
        if ea in path:
            break
        path.append(ea)
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        if mnemonic == 'jmp' and idc.get_operand_type(ea, 0) == int(idaapi.o_near):
            ea = int(idc.get_operand_value(ea, 0))
            continue
        if mnemonic.startswith('j') or mnemonic.startswith('ret'):
            break
        ea = int(idc.next_head(ea, idaapi.BADADDR))
    return path


def scaled_by_four(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_phrase), int(idaapi.o_displ)) and op.specflag1:
            sib = int(op.specflag2)
            if ((sib >> 3) & 7) != 4 and (1 << ((sib >> 6) & 3)) == 4:
                return True
    return False


def flow_graph(owner):
    blocks = list(ida_gdl.FlowChart(ida_funcs.get_func(int(owner))))
    bounds = {int(block.start_ea): int(block.end_ea) for block in blocks}
    successors = {start: set() for start in bounds}
    predecessors = {start: set() for start in bounds}
    for block in blocks:
        for successor in block.succs():
            target = int(successor.start_ea)
            if target in bounds:
                successors[int(block.start_ea)].add(target)
                predecessors[target].add(int(block.start_ea))
    return bounds, successors, predecessors


def reachable(seeds, edges):
    seen = set()
    pending = list(seeds)
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        pending.extend(edges[node])
    return seen


def block_of(bounds, ea):
    return next((start for start, end in bounds.items() if start <= int(ea) < end), None)


def in_blocks(bounds, blocks, ea):
    return any(bounds[start] > int(ea) >= start for start in blocks)


def sequence_body_ok(target):
    entries = scan(int(target))
    if not entries:
        return False
    reads_global = any(entry['targets'] for entry in entries)
    offsets = set()
    for entry in entries:
        for op in entry['insn'].ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_displ) and reg4(op) not in ('esp', 'ebp'):
                offsets.add(signed32(op.addr))
    return reads_global and all(offset in offsets for offset in GROUP_OFFSETS)


def locate(owner):
    sites = hash_compares(owner)
    if len(sites) != 1:
        return {'error': 'lookup owner must have exactly one pszin[0] == # compare',
                'owner': hex(owner), 'sites': [hex(site) for site in sites]}
    branches = hash_branches(sites[0])
    if branches is None:
        return {'error': '# compare is not followed by jz/jnz', 'site': hex(sites[0])}
    equal, not_equal = branches

    calls = [ea for ea in straight_line(equal, owner) if (idc.print_insn_mnem(ea) or '').lower() == 'call']
    if len(calls) != 2:
        return {'error': '# branch must call atoi then SequenceGetSentenceByIndex',
                'calls': [hex(ea) for ea in calls]}
    sequence = local_call_target(calls[1])
    if sequence is None or sequence == int(owner) or not sequence_body_ok(sequence):
        return {'error': 'SequenceGetSentenceByIndex call target failed validation', 'call': hex(calls[1])}

    entries = scan(owner)
    by_ea = {entry['ea']: entry for entry in entries}
    count = None
    for ea in straight_line(not_equal, owner):
        entry = by_ea.get(ea)
        if entry is None or not entry['targets']:
            continue
        if len(entry['targets']) != 1 or scaled_by_four(entry['insn']):
            return {'error': 'first not-# global access is not a scalar count', 'insn': hex(ea)}
        count = next(iter(entry['targets']))
        break
    if count is None:
        return {'error': 'not-# branch does not read the sentence count'}

    bounds, successors, predecessors = flow_graph(owner)
    loops = set()
    for entry in entries:
        if count not in entry['targets']:
            continue
        block = block_of(bounds, entry['ea'])
        if block is None or block not in reachable(successors[block], successors):
            continue
        loops.add(frozenset(reachable([block], successors) & reachable([block], predecessors)))
    if len(loops) != 1:
        return {'error': 'sentence count must be re-read by exactly one loop', 'loops': len(loops)}
    loop = next(iter(loops))
    region = set(loop)
    region.update(start for start in bounds if start not in loop and successors[start] & loop)
    arrays = set()
    for entry in entries:
        if in_blocks(bounds, region, entry['ea']):
            arrays.update(target for target in entry['targets'] if target != count)
    if len(arrays) != 1:
        return {'error': 'sentence loop must touch exactly one sentence array',
                'arrays': [hex(item) for item in arrays]}
    array = next(iter(arrays))
    if not any(array in entry['targets'] and scaled_by_four(entry['insn']) for entry in entries):
        return {'error': 'sentence array has no [reg*4] element access', 'array': hex(array)}

    located = {}
    for key, gv in (('count', count), ('array', array)):
        carrier = first_addressable(entries, [index for index, entry in enumerate(entries)
                                               if gv in entry['targets'] and entry['disp']])
        if carrier is None:
            return {'error': 'no addressable reference for %s' % key, 'gv': hex(gv)}
        located[key] = access(carrier, gv)
    return {'sequence': hex(sequence), **located}


load = ida_funcs.get_func(OWNER)
if load is None or int(load.start_ea) != OWNER:
    result = {'error': 'VOX_LoadSound artifact is not a function start'}
else:
    own_sites = hash_compares(OWNER)
    helpers = sorted(callee for callee in direct_calls(OWNER) if hash_compares(callee))
    if len(own_sites) == 1 and not helpers:
        lookup, mode = OWNER, 'inlined'
    elif not own_sites and len(helpers) == 1:
        lookup, mode = helpers[0], 'standalone'
    else:
        lookup, mode = None, None
        result = {'error': 'sentence lookup is missing or ambiguous',
                  'own_sites': [hex(site) for site in own_sites], 'helpers': [hex(item) for item in helpers]}
    if lookup is not None:
        located = locate(lookup)
        if located.get('error'):
            result = located
        else:
            result = {'pointer_size': 4, 'mode': mode, 'lookup': hex(lookup), **located}
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
    _ = old_yaml_map
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in REQUIRED_NAMES}
    if any(output is None for output in outputs.values()):
        return False
    lookup_output = _output_for_symbol(expected_outputs, LOOKUP_NAME)

    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_NAME)
    if owner is None:
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"])})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    standalone = located["mode"] == "standalone"
    if lookup_output is not None and not standalone:
        if debug:
            print(f"{skill_name}: {LOOKUP_NAME} is inlined into {OWNER_NAME} on this build")
        return False

    lookup_ea = int(located["lookup"], 0)
    if standalone:
        context = await owner_context(session, lookup_ea, image_base, LOOKUP_NAME)
    else:
        context = owner if lookup_ea == owner["owner_ea"] else None
    if context is None:
        return False
    sequence = await inspect_func(session, int(located["sequence"], 0), image_base, SEQUENCE_NAME)
    if sequence is None:
        return False

    globals_ = {COUNT_NAME: located["count"], ARRAY_NAME: located["array"]}
    if not await write_located_globals(session, expected_outputs, platform, image_base, context, globals_):
        return False
    write_func_yaml(outputs[SEQUENCE_NAME], sequence)
    if lookup_output is not None:
        function = dict(context["function"])
        if context["allow_across"]:
            function["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(lookup_output, func_payload(function))
    return True
