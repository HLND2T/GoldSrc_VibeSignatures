#!/usr/bin/env python3
"""Locate Sys_InitGame plus pmainwindow and maindc from its GL_SetMode call.

Sys_InitGame (engine/sys_dll2.cpp) stringifies TRACEINIT(Sys_InitLauncherInterface(),
Sys_ShutdownLauncherInterface()), so the exact C literal
"Sys_InitLauncherInterface()" is referenced only inside that function.
"Sys_ShutdownLauncherInterface()" is shared with Sys_ShutdownGame and is not
used as a discovery anchor.

The same function then calls GL_SetMode(*pmainwindow, &maindc, &baseRC, ...)
(GoldSrc/HL25 six-arg, or SvEngine three-arg). That call is the unique direct
call whose arg0 is a dereference of one writable global and whose arg1/arg2
are addresses of two other writable globals. Those three objects are
pmainwindow, maindc, and baseRC; this finder emits the first two.

Linux ELF names are _Z12Sys_InitGamePcS_Pvi, pmainwindow, and maindc; artifacts
use the demangled Sys_InitGame together with the unmangled global names.
Discovery uses the current IDB only: no byte signature, no prior artifact, and
no LLM output participates.
"""

import inspect

from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    owner_context,
    run_walk,
)
from ida_preprocessor_scripts import x86_call_arguments
from ida_analyze_util import _output_for_symbol, write_func_yaml

FUNC_NAME = "Sys_InitGame"
PMAINWINDOW_NAME = "pmainwindow"
MAINDC_NAME = "maindc"
LITERAL = "Sys_InitLauncherInterface()"
LOOKBACK = 12

WALK = (
    inspect.getsource(x86_call_arguments)
    + r"""
import ida_frame

LITERAL = values['literal']
LOOKBACK = int(values['lookback'])


def last_value_load(entries, index, reg):
    for previous in range(index - 1, max(-1, index - LOOKBACK - 1), -1):
        entry = entries[previous]
        mnemonic = entry['mnem']
        if mnemonic == 'call' or mnemonic.startswith('j') or mnemonic in ('ret', 'retn', 'retf', 'loop'):
            return None
        insn = entry['insn']
        destination = insn.ops[0]
        if int(destination.type) != int(idaapi.o_reg) or reg4(destination) != reg:
            continue
        if mnemonic == 'lea':
            return None
        if (
            mnemonic == 'mov'
            and len(entry['targets']) == 1
            and not entry['written']
            and entry['disp']
        ):
            gv = next(iter(entry['targets']))
            if is_writable_data(gv):
                return entry, gv
        return None
    return None


def tagged_imm(kind, gv, entry):
    located = access(entry, gv)
    if located is None or not entry['disp']:
        return None
    return (kind, located)


def encode_source(entries, index, op, op_index, stack_pointer):
    entry = entries[index]
    kind = int(op.type)
    if kind == int(idaapi.o_imm):
        value = int(op.value) & 0xFFFFFFFF
        if is_writable_data(value):
            tagged = tagged_imm('addr', value, entry)
            if tagged is not None:
                return ('imm', tagged)
        return ('imm', value)
    if kind == int(idaapi.o_reg):
        return ('reg', reg4(op))
    if kind in (int(idaapi.o_near), int(idaapi.o_far)):
        return ('imm', int(idc.get_operand_value(entry['ea'], op_index)) & 0xFFFFFFFF)
    if kind not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
        return ('unknown', None)
    text = (idc.print_operand(entry['ea'], op_index) or '').lower()
    if '[esp' in text and not any(
        register in text for register in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')
    ):
        displacement = signed32(op.addr) if kind == int(idaapi.o_displ) else 0
        if ida_ua.get_dtype_size(op.dtype) == 4 and displacement % 4 == 0:
            return ('stack', stack_pointer + displacement)
        return ('unknown', None)
    loaded = last_value_load(entries, index, reg4(op))
    if loaded is None:
        return ('unknown', None)
    load_entry, gv = loaded
    tagged = tagged_imm('deref', gv, load_entry)
    return ('imm', tagged) if tagged is not None else ('unknown', None)


owner = exact_string_owner(LITERAL)
if owner is None:
    result = {'error': 'Sys_InitLauncherInterface() has no single owning function'}
else:
    func = ida_funcs.get_func(int(owner))
    entries = scan(owner)
    if func is None or entries is None:
        result = {'error': 'Sys_InitGame owner is not a function start'}
    else:
        got_base, got_register = got_anchor(owner)
        compiler_exits = compiler_noreturn_imports()
        noreturn_calls = {
            entry['ea'] for entry in entries
            if entry['mnem'] == 'call' and local_call_target(entry['ea']) in compiler_exits
        }
        flow = decode_function_flow(
            func,
            [entry['ea'] for entry in entries],
            noreturn_calls=noreturn_calls,
        )
        code = []
        for index, entry in enumerate(entries):
            insn = entry['insn']
            mnemonic = entry['mnem']
            stack_pointer = int(ida_frame.get_spd(func, entry['ea']))
            operands = []
            for op_index, op in enumerate(insn.ops):
                kind = int(op.type)
                if kind == int(idaapi.o_void):
                    break
                if kind == int(idaapi.o_reg) and (op_index == 0 or ida_ua.get_dtype_size(op.dtype) == 4):
                    operands.append(('reg', reg4(op)))
                else:
                    operands.append(encode_source(entries, index, op, op_index, stack_pointer))
            if mnemonic == 'lea' and len(operands) == 2 and entry['disp'] and len(entry['targets']) == 1:
                source = insn.ops[1]
                address = None
                if int(source.type) == int(idaapi.o_mem):
                    address = int(source.addr) & 0xFFFFFFFF
                elif (
                    int(source.type) == int(idaapi.o_displ)
                    and got_base is not None
                    and reg4(source) == got_register
                ):
                    address = (got_base + signed32(source.addr)) & 0xFFFFFFFF
                gv = next(iter(entry['targets']))
                if address == gv and is_writable_data(gv):
                    mnemonic = 'mov'
                    tagged = tagged_imm('addr', gv, entry)
                    if tagged is not None:
                        operands[1] = ('imm', tagged)
            if operands and operands[0][0] == 'reg' and ida_ua.get_dtype_size(insn.ops[0].dtype) != 4:
                mnemonic = 'unknown_write'
            code.append(
                {
                    'mnem': mnemonic,
                    'ops': operands,
                    'sp': stack_pointer,
                    'ea': entry['ea'],
                    'successors': flow[entry['ea']],
                    'disp': entry['disp'],
                    'len': entry['len'],
                    'disasm': entry['disasm'],
                }
            )
        found = []
        for index, instruction in enumerate(code):
            if instruction['mnem'] != 'call':
                continue
            if int(entries[index]['insn'].ops[0].type) != int(idaapi.o_near):
                continue
            args = recover_call_arguments(code, index, 3)
            if not (
                isinstance(args[0], tuple) and args[0] and args[0][0] == 'deref'
                and isinstance(args[1], tuple) and args[1] and args[1][0] == 'addr'
                and isinstance(args[2], tuple) and args[2] and args[2][0] == 'addr'
            ):
                continue
            window, maindc, baserc = args[0][1], args[1][1], args[2][1]
            if len({window['gv_ea'], maindc['gv_ea'], baserc['gv_ea']}) != 3:
                continue
            found.append((window, maindc))
        identities = {(item[0]['gv_ea'], item[1]['gv_ea']) for item in found}
        if len(identities) != 1:
            result = {
                'error': 'GL_SetMode window/HDC pair is not unique: %s'
                % [(a, b) for a, b in sorted(identities)]
            }
        else:
            window, maindc = found[0]
            result = {
                'pointer_size': 4,
                'owner_ea': hex(owner),
                'pmainwindow': window,
                'maindc': maindc,
            }
"""
)


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
    _ = old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    func_output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if (
        func_output is None
        or _output_for_symbol(expected_outputs, PMAINWINDOW_NAME) is None
        or _output_for_symbol(expected_outputs, MAINDC_NAME) is None
    ):
        return False

    located = await run_walk(session, WALK, {"literal": LITERAL, "lookback": LOOKBACK})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    owner_ea = int(located["owner_ea"], 0)

    function = await inspect_func(session, owner_ea, image_base, FUNC_NAME)
    owner = await owner_context(session, owner_ea, image_base, FUNC_NAME)
    if not function or owner is None:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {owner_ea:#x}")
        return False
    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {
            PMAINWINDOW_NAME: located["pmainwindow"],
            MAINDC_NAME: located["maindc"],
        },
    ):
        if debug:
            print(f"{skill_name}: failed to write pmainwindow/maindc at {owner_ea:#x}")
        return False
    write_func_yaml(func_output, function)
    if debug:
        print(
            f"{skill_name}: {FUNC_NAME}={owner_ea:#x} "
            f"{PMAINWINDOW_NAME}={located['pmainwindow']['gv_ea']} "
            f"{MAINDC_NAME}={located['maindc']['gv_ea']}"
        )
    return True
