#!/usr/bin/env python3
"""Locate Sys_InitArgv from RunListenServer's TraceInit("Sys_InitArgv( OrigCmd )").

Official source (engine/sys_dll2.cpp) runs
TraceInit("Sys_InitArgv( OrigCmd )", ...) and then Sys_InitArgv(OrigCmd),
whose only callee is COM_InitArgv. Take the first direct call after the
TraceInit call in the current RunListenServer body:

* De-inlined (every Windows build, hl-8684 hw.so): no jump separates the two
  calls; that callee is Sys_InitArgv. It must have exactly one real callee
  (COM_InitArgv), which RunListenServer itself never calls.
* Inlined (hl-10210, svencoop-8948 and svencoop-10257 hw.so): the inline argv
  tokenizer loop precedes the call, which therefore targets COM_InitArgv. GCC
  still emits the uncalled out-of-line Sys_InitArgv body; it is the unique
  COM_InitArgv caller other than RunListenServer whose only real callee is
  COM_InitArgv (CDedicatedServerAPI::Init is the other caller and has many).

PIC ``__x86.get_pc_thunk.*`` helpers are not real callees. ELF/DWARF names
establish the identities; stripped svencoop-10257 hw.so is matched by shape.
"""

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._vgui_paint_common import function_address

TARGET_FUNC_NAME = "Sys_InitArgv"
OWNER_FUNC_NAME = "RunListenServer"
FUNC_FIELDS = ("func_name", "func_va", "func_rva", "func_size", "func_sig")

LOCATE_SYS_INITARGV = r"""
ARGV_STR = 'Sys_InitArgv( OrigCmd )'
owner = int(values['owner'])

def exact_strings(text):
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    return [int(item.ea) for item in strings if str(item) == text]

def is_pc_thunk(ea):
    body = list(idautils.FuncItems(int(ea))) if ida_funcs.get_func(int(ea)) else []
    return (
        len(body) == 2
        and idc.print_insn_mnem(body[0]) == 'mov'
        and idc.print_operand(body[0], 1) in ('[esp]', '[esp+0]')
        and idc.print_insn_mnem(body[1]) in ('retn', 'ret')
    )

def direct_call_target(ea):
    if not idaapi.is_call_insn(int(ea)) or idc.get_operand_type(int(ea), 0) != ida_ua.o_near:
        return None
    target = int(idc.get_operand_value(int(ea), 0))
    fn = ida_funcs.get_func(target)
    if fn is None or int(fn.start_ea) != target or is_pc_thunk(target):
        return None
    return target

def real_callees(func_ea):
    targets = set()
    for ea in idautils.FuncItems(int(func_ea)):
        target = direct_call_target(ea)
        if target is not None:
            targets.add(target)
    return targets

def direct_callers(target):
    owners = set()
    for ref in idautils.CodeRefsTo(int(target), 0):
        fn = ida_funcs.get_func(int(ref))
        if fn is not None and direct_call_target(ref) == int(target):
            owners.add(int(fn.start_ea))
    return owners

def locate():
    fn = ida_funcs.get_func(owner)
    if fn is None or int(fn.start_ea) != owner:
        return {'error': 'RunListenServer has no exact function boundary'}
    strs = exact_strings(ARGV_STR)
    if len(strs) != 1:
        return {'error': 'Sys_InitArgv( OrigCmd ) string count %d' % len(strs)}
    sites = sorted(
        int(ref) for ref in idautils.DataRefsTo(strs[0])
        if ida_funcs.get_func(int(ref)) and int(ida_funcs.get_func(int(ref)).start_ea) == owner
    )
    if len(sites) != 1:
        return {'error': 'string reference sites in RunListenServer %r' % [hex(x) for x in sites]}
    calls = []
    for ea in idautils.FuncItems(owner):
        if int(ea) > sites[0] and direct_call_target(ea) is not None:
            calls.append(int(ea))
            if len(calls) == 2:
                break
    if len(calls) != 2:
        return {'error': 'TraceInit/Sys_InitArgv call pair not found'}
    traceinit_call, argv_call = calls
    first = direct_call_target(argv_call)
    inlined = any(
        idc.print_insn_mnem(ea).startswith('j')
        for ea in idautils.FuncItems(owner)
        if traceinit_call < int(ea) < argv_call
    )
    owner_callees = real_callees(owner)
    if inlined:
        com_init_argv = first
        candidates = sorted(
            caller for caller in direct_callers(com_init_argv)
            if caller != owner and real_callees(caller) == {com_init_argv}
        )
        if len(candidates) != 1:
            return {'error': 'out-of-line Sys_InitArgv candidates %r' % [hex(x) for x in candidates]}
        target = candidates[0]
    else:
        target = first
        callees = real_callees(target)
        if len(callees) != 1:
            return {'error': 'Sys_InitArgv real callees %r' % [hex(x) for x in sorted(callees)]}
        com_init_argv = next(iter(callees))
        if com_init_argv in owner_callees:
            return {'error': 'RunListenServer calls the COM_InitArgv candidate directly'}
    return {
        'target': target,
        'com_init_argv': com_init_argv,
        'inlined': inlined,
        'argv_call': argv_call,
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
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    owner = function_address(new_binary_dir, OWNER_FUNC_NAME, platform)
    if platform not in {"windows", "linux"} or output is None or owner is None:
        return False
    located = await run_walk(session, LOCATE_SYS_INITARGV, {"owner": owner})
    target = located.get("target")
    if located.get("error") or isinstance(target, bool) or not isinstance(target, int):
        if debug:
            print(f"{skill_name}: locator failed {located}")
        return False
    function = await _inspect_function_via_mcp(session, target, image_base, TARGET_FUNC_NAME)
    if not function or not function.get("func_sig") or int(function["func_va"], 0) != target:
        if debug:
            print(f"{skill_name}: failed to inspect {hex(target)}")
        return False
    if debug:
        print(
            f"{skill_name}: target={hex(target)} inlined={located['inlined']} "
            f"COM_InitArgv={hex(located['com_init_argv'])} call={hex(located['argv_call'])}"
        )
    write_func_yaml(output, {field: function[field] for field in FUNC_FIELDS})
    return True
