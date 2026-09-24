"""Recover disconnection state from the validated explanation setters.

Both setters format into a private 1024-byte buffer, copy at most 255 bytes to
the public reason, terminate byte 255, and suppress printing a leading '#'.
The basic setter also stores true to gfExtendedError. The target binaries do
not consistently make that store in the extended setter, despite the source
reference doing so. The explicit terminator and '#' read identify the public
256-byte array independently of compiler-specific Q_strncpy inlining or PIC.
"""

from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

REASON_SIZE = 256

WALK = r"""
import ida_gdl

OWNER = int(values['owner'], 0)
REASON_SIZE = int(values['reason_size'])
WANT_FLAG = bool(values['want_flag'])


def width(op):
    return int(ida_ua.get_dtype_size(op.dtype))


def is_true_store(entries, index):
    entry = entries[index]
    if entry['mnem'] != 'mov' or width(entry['insn'].ops[0]) != 4:
        return False
    source = entry['insn'].ops[1]
    if int(source.type) == int(idaapi.o_imm):
        return int(source.value) == 1
    if int(source.type) != int(idaapi.o_reg):
        return False
    register = reg4(source)
    function = ida_funcs.get_func(OWNER)
    block = next((block for block in ida_gdl.FlowChart(function)
                  if int(block.start_ea) <= int(entry['ea']) < int(block.end_ea)), None)
    if block is None:
        return False
    for previous in reversed(entries[:index]):
        if int(previous['ea']) < int(block.start_ea):
            break
        if previous['mnem'] == 'call':
            return False
        destination = previous['insn'].ops[0]
        if int(destination.type) != int(idaapi.o_reg) or reg4(destination) != register:
            continue
        assigned = previous['insn'].ops[1]
        return (previous['mnem'] == 'mov' and int(assigned.type) == int(idaapi.o_imm)
                and int(assigned.value) == 1)
    return False


def has_hash_guard(entries, base):
    for index, entry in enumerate(entries):
        if base not in entry['targets']:
            continue
        insn = entry['insn']
        source = insn.ops[1]
        if (entry['mnem'] == 'cmp' and width(insn.ops[0]) == 1
                and int(source.type) == int(idaapi.o_imm) and int(source.value) == ord('#')):
            return True
        # CoF sign-extends the byte into a register before comparing it.
        if entry['mnem'] not in ('movsx', 'movzx') or width(source) != 1:
            continue
        destination = insn.ops[0]
        if int(destination.type) != int(idaapi.o_reg) or index + 1 >= len(entries):
            continue
        following = entries[index + 1]
        comparison = following['insn']
        if (following['mnem'] == 'cmp'
                and int(comparison.ops[0].type) == int(idaapi.o_reg)
                and reg4(comparison.ops[0]) == reg4(destination)
                and int(comparison.ops[1].type) == int(idaapi.o_imm)
                and int(comparison.ops[1].value) == ord('#')):
            return True
    return False


entries = scan(OWNER)
if entries is None:
    result = {'error': 'explanation artifact is not a function start'}
else:
    copy_limit = any(
        int(op.type) == int(idaapi.o_imm) and int(op.value) == REASON_SIZE - 1
        for entry in entries for op in entry['insn'].ops
        if int(op.type) != int(idaapi.o_void)
    )
    candidates = []
    for entry in entries:
        insn = entry['insn']
        if (entry['mnem'] != 'mov' or width(insn.ops[0]) != 1
                or int(insn.ops[1].type) != int(idaapi.o_imm)
                or int(insn.ops[1].value) != 0 or len(entry['written']) != 1):
            continue
        end = next(iter(entry['written']))
        base = end - (REASON_SIZE - 1)
        if not is_writable_data(base):
            continue
        if not has_hash_guard(entries, base):
            continue
        references = [index for index, other in enumerate(entries)
                      if base in other['targets'] and other['disp']]
        carrier = first_addressable(entries, references)
        if carrier is not None:
            candidates.append((base, carrier))
    if not copy_limit or len(candidates) != 1:
        result = {'error': 'public 256-byte reason array is missing or ambiguous',
                  'copy_limit': copy_limit, 'candidates': [hex(item[0]) for item in candidates]}
    else:
        reason, carrier = candidates[0]
        located = {'reason': access(carrier, reason)}
        if WANT_FLAG:
            flags = []
            for index, entry in enumerate(entries):
                if len(entry['written']) != 1 or not is_true_store(entries, index):
                    continue
                address = next(iter(entry['written']))
                if address == reason or address == reason + REASON_SIZE - 1:
                    continue
                references = [j for j, item in enumerate(entries)
                              if address in item['targets'] and item['disp']]
                carrier = first_addressable(entries, references)
                if carrier is not None:
                    flags.append((address, carrier))
            if len(flags) != 1:
                result = {'error': 'gfExtendedError true store is missing or ambiguous',
                          'candidates': [hex(item[0]) for item in flags]}
            else:
                located['flag'] = access(flags[0][1], flags[0][0])
                result = {'pointer_size': 4, **located}
        else:
            result = {'pointer_size': 4, **located}
"""


async def preprocess_disconnection_globals(
    session,
    skill_name,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    owner_name,
    reason_name,
    include_flag,
    debug=False,
):
    names = (reason_name, "gfExtendedError") if include_flag else (reason_name,)
    if any(_output_for_symbol(expected_outputs, name) is None for name in names):
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, owner_name)
    if owner is None:
        return False
    located = await run_walk(
        session,
        WALK,
        {"owner": hex(owner["owner_ea"]), "reason_size": REASON_SIZE, "want_flag": include_flag},
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    context = await owner_context(session, owner["owner_ea"], image_base, owner_name)
    if context is None:
        return False
    globals_ = {reason_name: located["reason"]}
    if include_flag:
        globals_["gfExtendedError"] = located["flag"]
    if debug:
        print(f"{skill_name}: {globals_}")
    return await write_located_globals(session, expected_outputs, platform, image_base, context, globals_)
