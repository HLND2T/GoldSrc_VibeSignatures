#!/usr/bin/env python3
"""Recover COM_InitArgv, com_argc and com_argv from the Sys_InitArgv chain.

Official source (``engine/sys_dll2.cpp`` Sys_InitArgv, ``engine/common.c``
COM_InitArgv) lets Sys_InitArgv parse the raw command line, then call
COM_InitArgv to rebuild the externally visible ``cmdline`` cvar from that
temporary argv, and finally copy the engine's canonical arguments back out:

    COM_InitArgv(host_parms.argc, host_parms.argv);
    host_parms.argc = com_argc;
    host_parms.argv = com_argv;

MetaHook reuses exactly this pair instead of re-implementing the post-processing
(``-safe`` expansion and the trailing sentinel). All three targets come from one
deterministic walk over the existing, revalidated Sys_InitArgv artifact:

* ``COM_InitArgv`` is the single real callee of the Sys_InitArgv body. PIC
  ``__x86.get_pc_thunk.*`` helpers and PLT stubs are not real callees; GCC routes
  the call through a PLT entry whose GOT slot names the real body. The SvEngine
  builds share one COM_InitArgv across the engine and their bodies legitimately
  lack ``-safe``/``command_line``, so COM_InitArgv cannot be anchored on its own
  literal.
* ``com_argc`` and ``com_argv`` are the two writable globals that Sys_InitArgv
  copies *out* of the engine's argument store: Sys only reads them (it never
  writes them itself) while COM_InitArgv writes both. COM_InitArgv writes
  ``com_argc`` in its counting and ``-safe`` loops but assigns ``com_argv``
  exactly once, so the more frequently written global is ``com_argc`` and the
  other is ``com_argv``.

No address, byte signature, or prior artifact signature participates in
discovery. The generated function/global signatures only validate the located
outputs.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    func_payload,
    owner_context,
    run_walk,
)

SYS_INITARGV_NAME = "Sys_InitArgv"
COM_INITARGV_NAME = "COM_InitArgv"
ARGC_NAME = "com_argc"
ARGV_NAME = "com_argv"

WALK = r"""
import ida_funcs

owner = int(values['owner'], 0)


def pc_thunk(ea):
    name = idc.get_name(int(ea)) or ''
    if 'get_pc_thunk' in name:
        return True
    body = list(idautils.FuncItems(int(ea))) if ida_funcs.get_func(int(ea)) else []
    return (
        len(body) == 2
        and idc.print_insn_mnem(body[0]) == 'mov'
        and idc.print_operand(body[0], 1) in ('[esp]', '[esp+0]')
        and idc.print_insn_mnem(body[1]) in ('retn', 'ret')
    )


def real_callees(func_ea):
    found = set()
    for ea in idautils.FuncItems(int(func_ea)):
        target = local_call_target(ea)
        if target is not None and not pc_thunk(target):
            found.add(int(target))
    return sorted(found)


def addressable_write(entries, gv):
    for entry in entries:
        if gv in entry['written'] and entry['disp']:
            return entry
    return None


def locate():
    func = ida_funcs.get_func(owner)
    if func is None or int(func.start_ea) != owner:
        return {'error': 'Sys_InitArgv artifact is not a function start'}
    callees = real_callees(owner)
    if len(callees) != 1:
        return {'error': 'Sys_InitArgv real callees %r' % [hex(x) for x in callees]}
    com = callees[0]
    com_func = ida_funcs.get_func(com)
    if com_func is None or int(com_func.start_ea) != com:
        return {'error': 'COM_InitArgv is not a function start'}
    sys_entries = scan(owner)
    com_entries = scan(com)
    if sys_entries is None or com_entries is None:
        return {'error': 'failed to decode Sys_InitArgv or COM_InitArgv'}
    sys_touched = set()
    sys_written = set()
    for entry in sys_entries:
        sys_touched.update(int(gv) for gv in entry['targets'])
        sys_written.update(int(gv) for gv in entry['written'])
    com_written = {}
    for entry in com_entries:
        for gv in entry['written']:
            com_written.setdefault(int(gv), []).append(entry)
    candidates = sorted((sys_touched - sys_written) & set(com_written))
    if len(candidates) != 2:
        return {'error': 'argv store candidates %r' % [hex(x) for x in candidates]}
    ranked = sorted(candidates, key=lambda gv: (-len(com_written[gv]), gv))
    if len(com_written[ranked[0]]) <= len(com_written[ranked[1]]):
        return {'error': 'com_argc/com_argv write counts are not distinct'}
    argc_entry = addressable_write(com_entries, ranked[0])
    argv_entry = addressable_write(com_entries, ranked[1])
    if argc_entry is None or argv_entry is None:
        return {'error': 'a com_argc/com_argv store carries no four-byte displacement'}
    return {
        'com': hex(com),
        'argc': access(argc_entry, ranked[0]),
        'argv': access(argv_entry, ranked[1]),
    }


result = locate()
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
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, SYS_INITARGV_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: missing or invalid {SYS_INITARGV_NAME} artifact")
        return False
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"])})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or not isinstance(located.get("com"), str):
        return False
    com_owner = await owner_context(session, int(located["com"], 0), image_base, COM_INITARGV_NAME)
    if com_owner is None:
        if debug:
            print(f"{skill_name}: failed to inspect COM_InitArgv at {located['com']}")
        return False
    com_output = _output_for_symbol(expected_outputs, COM_INITARGV_NAME)
    if com_output is None:
        if debug:
            print(f"{skill_name}: no output path for {COM_INITARGV_NAME}")
        return False
    write_func_yaml(com_output, func_payload(com_owner["function"]))
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        com_owner,
        {ARGC_NAME: located["argc"], ARGV_NAME: located["argv"]},
    )
