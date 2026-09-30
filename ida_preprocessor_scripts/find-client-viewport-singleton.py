#!/usr/bin/env python3
"""Recover the viewport object exposed as VClientVGUI001.

The current InterfaceReg constructor arguments identify its factory. The
factory's verified return and the class's primary/secondary RTTI tables are
matched to paired vptr installs in its static initialization or constructor.
No interface-to-object displacement, slot, address or byte pattern discovers
the object. The final signature comes from an instruction that references the
verified complete object, not from an interface pointer global.

This direct path avoids an LLM guessing among the several viewport interfaces.
MSVC 4554 uses NEG/SBB/AND in the factory; GCC can inline construction into the
registration initializer. Both forms are verified against every configured
CS/CZ/CZDS client platform. Old artifacts are never discovery inputs.
"""

import inspect

from ida_analyze_util import _output_for_symbol
import ida_preprocessor_scripts._client_viewport_singleton as _client_viewport_singleton
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_patch_common import CALL_FLOW_PY
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._vgui_paint_common import FLOW_SOURCE, IDA_FLOW

WALK = (
    FLOW_SOURCE
    + IDA_FLOW
    + CALL_FLOW_PY
    + inspect.getsource(_client_viewport_singleton)
    + r"""
import ida_auto

X86_MAX_INSTRUCTION_BYTES = 15


def recover_linear_owner(site):
    owner = ida_funcs.get_func(site)
    if owner is not None:
        return owner
    segment = ida_segment.getseg(site)
    cursor = site
    for _ in range(MAX_PATH_INSTRUCTIONS):
        previous = idc.prev_head(cursor, segment.start_ea)
        if previous == idaapi.BADADDR or previous >= cursor:
            return None
        instruction = idautils.DecodeInstruction(previous)
        terminal = instruction and instruction.get_canon_mnem() in ('ret', 'retn')
        if instruction and instruction.get_canon_mnem() == 'jmp':
            following = idautils.DecodeInstruction(previous + int(instruction.size))
            terminal = following and following.get_canon_mnem() in ('nop', 'int3')
        if terminal:
            cursor = previous + int(instruction.size)
            break
        cursor = previous
    else:
        return None
    while cursor <= site:
        instruction = idautils.DecodeInstruction(cursor)
        if instruction is None:
            return None
        if instruction.get_canon_mnem() not in ('nop', 'int3'):
            break
        cursor += int(instruction.size)
    entry = cursor
    if not list(idautils.CodeRefsTo(entry, 0)):
        return None
    for _ in range(MAX_PATH_INSTRUCTIONS):
        instruction = idautils.DecodeInstruction(cursor)
        if instruction is None:
            return None
        mnemonic = instruction.get_canon_mnem()
        cursor += int(instruction.size)
        terminal = mnemonic in ('ret', 'retn')
        if mnemonic == 'jmp' and instruction.ops[0].type == idaapi.o_near:
            callee = ida_funcs.get_func(int(instruction.ops[0].addr))
            terminal = callee is not None and int(callee.start_ea) == int(instruction.ops[0].addr)
        if terminal:
            if not entry <= site < cursor:
                return None
            ida_funcs.add_func(entry, cursor)
            ida_auto.auto_wait()
            return ida_funcs.get_func(site)
        if mnemonic.startswith(('j', 'loop')):
            return None
    return None


def locate():
    if idaapi.inf_is_64bit():
        raise ValueError('viewport singleton requires x86')
    platform = values['platform']
    needle = b'VClientVGUI001\0'
    literals = set()
    for start in idautils.Segments():
        segment = ida_segment.getseg(start)
        if segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea-segment.start_ea) or b''
        index = 0
        while True:
            index = data.find(needle, index)
            if index < 0:
                break
            literals.add(int(segment.start_ea)+index)
            index += 1
    if len(literals) != 1:
        raise ValueError('VClientVGUI001 literal is absent or ambiguous')
    literal = next(iter(literals))
    sites = {int(ref.frm) for ref in idautils.XrefsTo(literal, 0) if is_code_address(int(ref.frm))}
    if platform == 'windows':
        # Some old warm databases omit both the CRT initializer and its xref.
        # Search the current literal's encoded address, then require the decoded
        # PUSH operand to equal it. This is an operand xref, not a byte signature.
        encoded = literal.to_bytes(WORD_SIZE, 'little')
        for start in idautils.Segments():
            segment = ida_segment.getseg(start)
            if not (segment.perm & ida_segment.SEGPERM_EXEC):
                continue
            data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea-segment.start_ea) or b''
            index = 0
            while True:
                index = data.find(encoded, index)
                if index < 0:
                    break
                site = int(segment.start_ea)+index-1
                instruction = idautils.DecodeInstruction(site) if index else None
                if (instruction is not None and instruction.get_canon_mnem() == 'push'
                        and instruction.ops[0].type == idaapi.o_imm
                        and int(instruction.ops[0].value) == literal):
                    sites.add(site)
                index += 1
    factories = set()
    for site in sorted(sites):
        owner = ida_funcs.get_func(site)
        # CZDS 8684's warm IDB omits this CRT initializer. Its exact literal
        # reference is the entry's first PUSH; require the complete bounded
        # straight-line registration before defining that callable boundary.
        if owner is None and platform == 'windows':
            first = idautils.DecodeInstruction(site)
            if (first is not None and first.get_canon_mnem() == 'push'
                    and first.ops[0].type == idaapi.o_imm and int(first.ops[0].value) == literal):
                cursor = site
                for _ in range(MAX_PATH_INSTRUCTIONS):
                    instruction = idautils.DecodeInstruction(cursor)
                    if instruction is None:
                        break
                    mnemonic = instruction.get_canon_mnem().lower()
                    cursor += int(instruction.size)
                    if mnemonic in ('ret', 'retn'):
                        ida_funcs.add_func(site, cursor)
                        ida_auto.auto_wait()
                        owner = ida_funcs.get_func(site)
                        break
                    if mnemonic.startswith(('j', 'loop')):
                        break
        if owner is None:
            continue
        entries = scan(int(owner.start_ea))
        code = decoded_calls(int(owner.start_ea), entries)
        arity = 2 if platform == 'windows' else 3
        for index, item in enumerate(code):
            if item['mnem'] != 'call' or local_call_target(item['ea']) is None:
                continue
            arguments = recover_call_arguments(code, index, arity)
            callback, name = arguments[-2:]
            if name == literal and isinstance(callback, int) and is_code_address(callback):
                function = ida_funcs.get_func(callback)
                if function is None:
                    ida_funcs.add_func(callback)
                    function = ida_funcs.get_func(callback)
                if function and int(function.start_ea) == callback:
                    factories.add(callback)
    if len(factories) != 1:
        raise ValueError('VClientVGUI001 registered factory is absent or ambiguous')
    factory = next(iter(factories))
    interface = constant_factory_return(decoded_calls(factory, scan(factory)))
    if not isinstance(interface, int) or not is_writable_data(interface) or interface % WORD_SIZE:
        raise ValueError('factory does not return a verified static interface address')
    primary = int(table_for(values['class_name'])['vtable_va'], 0)

    def secondary_offset(table):
        if not is_readable_data(table) or not is_code_address(int(ida_bytes.get_dword(table))):
            return None
        if platform == 'linux':
            if ida_bytes.get_dword(table-4) != ida_bytes.get_dword(primary-4):
                return None
            offset = -signed32(ida_bytes.get_dword(table-8))
        else:
            locator = int(ida_bytes.get_dword(table-4))
            primary_locator = int(ida_bytes.get_dword(primary-4))
            if (not is_readable_data(locator) or not is_readable_data(primary_locator)
                    or ida_bytes.get_dword(locator) != 0
                    or ida_bytes.get_dword(locator+12) != ida_bytes.get_dword(primary_locator+12)):
                return None
            offset = int(ida_bytes.get_dword(locator+4))
        return offset if 0 <= offset <= interface and offset % WORD_SIZE == 0 else None

    owners = set()
    for address in (primary, primary-8) if platform == 'linux' else (primary,):
        for ref in idautils.XrefsTo(address, 0):
            owner = ida_funcs.get_func(int(ref.frm))
            if owner and is_code_address(int(ref.frm)):
                owners.add(int(owner.start_ea))
    if platform == 'windows':
        # CZDS 8684 also has decoded constructor instructions without a function
        # or vptr xref. Recover only an actual MOV of the current RTTI address
        # point and its return-delimited callable body in the no-save worker.
        encoded = primary.to_bytes(WORD_SIZE, 'little')
        for start in idautils.Segments():
            segment = ida_segment.getseg(start)
            if not (segment.perm & ida_segment.SEGPERM_EXEC):
                continue
            data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea-segment.start_ea) or b''
            index = 0
            while True:
                index = data.find(encoded, index)
                if index < 0:
                    break
                slot = int(segment.start_ea)+index
                for back in range(1, X86_MAX_INSTRUCTION_BYTES):
                    site = slot-back
                    if ida_bytes.get_item_head(site) != site:
                        continue
                    instruction = idautils.DecodeInstruction(site)
                    if (instruction and instruction.get_canon_mnem() == 'mov'
                            and instruction.ops[0].type in (idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ)
                            and instruction.ops[1].type == idaapi.o_imm
                            and int(instruction.ops[1].value) == primary
                            and int(instruction.ops[1].offb) == back):
                        owner = recover_linear_owner(site)
                        if owner:
                            owners.add(int(owner.start_ea))
                index += 1
    cache = {}

    def flow(owner):
        if owner not in cache:
            cache[owner] = flow_at(owner, platform)
        return cache[owner]

    evidence = set()

    def accept(initializer, stores):
        base = unique_constructed_base(interface, primary, stores, secondary_offset)
        if base is None or not is_writable_data(base):
            return
        for entry in scan(initializer) or []:
            offset = int(entry['disp'])
            raw = ida_bytes.get_bytes(entry['ea'], entry['len']) or b''
            if (offset and offset+WORD_SIZE <= len(raw)
                    and int.from_bytes(raw[offset:offset+WORD_SIZE], 'little') == base):
                evidence.add((base, initializer, entry['ea'], entry['len'], offset))

    for owner in sorted(owners):
        accept(owner, flow(owner)['stores'])
        for ref in idautils.CodeRefsTo(owner, 0):
            if local_call_target(int(ref)) != owner:
                continue
            caller = recover_linear_owner(int(ref))
            if caller is None:
                continue
            caller_ea = int(caller.start_ea)
            calls = [call for call in flow(caller_ea)['calls'] if call['ea'] == int(ref)]
            if len(calls) != 1:
                continue
            call = calls[0]
            receiver = call['registers'].get('ecx') if platform == 'windows' else call['stack_args'][0]
            if receiver and receiver[0] == 'const' and is_writable_data(receiver[1]):
                constructed = flow_at(owner, platform, entry_state=entry_state_from_call(call))
                accept(caller_ea, constructed['stores'])
    bases = {item[0] for item in evidence}
    if len(bases) != 1:
        raise ValueError('complete viewport object has no unique constructor/factory proof')
    return {'pointer_size': WORD_SIZE, 'factory': hex(factory), 'interface': hex(interface),
            'primary_table': hex(primary), 'base': hex(next(iter(bases))),
            'accesses': [{'base': hex(base), 'owner': hex(owner), 'site': hex(site),
                          'length': length, 'displacement': displacement}
                         for base, owner, site, length, displacement in sorted(evidence)]}


result = locate()
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
    classes = ("CounterStrikeViewport", "CZEROViewPort")
    selected = [
        (name, f"__g_{name}_singleton")
        for name in classes
        if _output_for_symbol(expected_outputs, f"__g_{name}_singleton") is not None
    ]
    if len(selected) != 1:
        return False
    class_name, symbol = selected[0]
    located = await run_walk(session, WALK, {"platform": platform, "class_name": class_name})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    for item in located["accesses"]:
        owner_ea = int(item["owner"], 0)
        function = await inspect_unique_function(session, class_name, owner_ea, image_base, debug)
        if function is None:
            continue
        owner = {
            "owner_ea": owner_ea,
            "owner_end": owner_ea + int(function["func_size"], 0),
            "function": function,
            "allow_across": bool(function.get("func_sig_allow_across_function_boundary")),
        }
        if await write_located_globals(
            session,
            expected_outputs,
            platform,
            image_base,
            owner,
            {
                symbol: {
                    "gv_ea": item["base"],
                    "insn_ea": item["site"],
                    "insn_len": item["length"],
                    "insn_disp": item["displacement"],
                },
            },
        ):
            return True
    return False
