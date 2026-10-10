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

# The trusted PR planner needs the full module path to map this dependency.
import ida_preprocessor_scripts._client_viewport_singleton as _client_viewport_singleton  # noqa: PLR0402
from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_patch_common import CALL_FLOW_PY
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._patch_signature_common import run_signature
from ida_preprocessor_scripts._vgui_paint_common import FLOW_SOURCE, IDA_FLOW

WALK = (
    FLOW_SOURCE
    + IDA_FLOW
    + CALL_FLOW_PY
    + inspect.getsource(_client_viewport_singleton)
    + r"""
X86_MAX_INSTRUCTION_BYTES = 15


def body_target(ea):
    if idc.get_operand_type(ea, 0) != idaapi.o_near:
        return None
    target = resolve_elf_plt(idc.get_operand_value(ea, 0))
    return int(target) if is_code_address(target) and not is_plt(target) else None


def linear_entries(start, tail_target=None):
    segment = ida_segment.getseg(start)
    if segment is None or not is_code_address(start):
        return None

    def decode(cursor):
        instruction = idautils.DecodeInstruction(cursor)
        if instruction is None or not segment.start_ea <= cursor < cursor + int(instruction.size) <= segment.end_ea:
            return None
        entries = scan(cursor, cursor + int(instruction.size))
        if not entries:
            return None
        return dict(entries[0], next_ea=cursor + int(instruction.size), direct=body_target(cursor))

    return bounded_body(start, decode, MAX_PATH_INSTRUCTIONS, tail_target=tail_target)


def linear_instructions(entries):
    instructions = []
    for entry in entries:
        insn = entry['insn']
        item = dict(ea=entry['ea'], next_ea=entry['next_ea'], mnem=entry['mnem'],
                    ops=[decoded_operand(op) for op in insn.ops if int(op.type) != idaapi.o_void],
                    writes=[flow_register(op) for i, op in enumerate(insn.ops)
                            if int(op.type) == idaapi.o_reg and changed_operand(insn, i)],
                    memory_writes=[decoded_operand(op) for i, op in enumerate(insn.ops)
                                   if int(op.type) in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase)
                                   and changed_operand(insn, i)],
                    direct=entry['direct'], tail=entry['mnem'] == 'jmp')
        if item['mnem'] in ('push', 'pop'):
            item['stack_width'] = ida_ua.get_dtype_size(insn.ops[0].dtype)
        if item['mnem'] == 'call':
            target = item['direct']
            function = ida_funcs.get_func(target) if target is not None else None
            if function is not None and int(function.start_ea) == target:
                try:
                    item['purge'] = callee_stack_purge(target)
                except ValueError:
                    return None
            else:
                callee = linear_entries(target) if target is not None else None
                if not callee:
                    return None
                operand = callee[-1]['insn'].ops[0]
                item['purge'] = int(operand.value) if int(operand.type) == idaapi.o_imm else 0
        instructions.append(item)
    return linear_stack(instructions)


def linear_call_code(entries):
    instructions = linear_instructions(entries)
    if instructions is None:
        return []
    code = []
    for item in instructions:
        operands = []
        for operand in item['ops']:
            if operand[0] in ('imm', 'reg'):
                operands.append(operand[:2])
            elif operand[0] == 'mem' and operand[1] == 'esp' and operand[3] is None:
                operands.append(('stack', item['sp'] + operand[2]))
            else:
                operands.append(('unknown', None))
        mnemonic = item['mnem']
        if (any(op[0] == 'reg' and op[2] != WORD_SIZE for op in item['ops'])
                or item['ops'] and item['ops'][0][0] == 'mem' and item['ops'][0][5] != WORD_SIZE):
            mnemonic = 'unknown_write'
        code.append(dict(item, mnem=mnemonic, ops=operands))
    return code


def recover_linear_owner(site, tail_target=None):
    segment = ida_segment.getseg(site)
    if segment is None:
        return None
    cursor = site
    for _ in range(MAX_PATH_INSTRUCTIONS):
        previous = idc.prev_head(cursor, segment.start_ea)
        if previous == idaapi.BADADDR or previous >= cursor:
            return None
        instruction = idautils.DecodeInstruction(previous)
        terminal = instruction and instruction.get_canon_mnem() in ('ret', 'retn')
        if instruction and instruction.get_canon_mnem() == 'jmp':
            following_ea = previous + int(instruction.size)
            following = idautils.DecodeInstruction(following_ea)
            terminal = (ida_bytes.is_align(ida_bytes.get_flags(following_ea))
                        or following and following.get_canon_mnem() in ('nop', 'int3'))
        if terminal:
            cursor = previous + int(instruction.size)
            break
        cursor = previous
    else:
        return None
    while cursor <= site:
        if ida_bytes.is_align(ida_bytes.get_flags(cursor)):
            following = int(ida_bytes.get_item_end(cursor))
            if following <= cursor:
                return None
            cursor = following
            continue
        instruction = idautils.DecodeInstruction(cursor)
        if instruction is None:
            return None
        if instruction.get_canon_mnem() not in ('nop', 'int3'):
            break
        cursor += int(instruction.size)
    entry = cursor
    if not list(idautils.CodeRefsTo(entry, 0)):
        return None
    entries = linear_entries(entry, tail_target)
    return entries if entries and any(item['ea'] == site for item in entries) else None


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
        code = []
        # A literal PUSH proves this registration suffix without trusting IDA's
        # enclosing function or its (possibly unrelated) stack-depth metadata.
        if platform == 'windows':
            first = idautils.DecodeInstruction(site)
            if (first is not None and first.get_canon_mnem() == 'push'
                    and first.ops[0].type == idaapi.o_imm and int(first.ops[0].value) == literal):
                entries = linear_entries(site)
                code = linear_call_code(entries) if entries else []
        elif owner is not None:
            code = decoded_calls(int(owner.start_ea), scan(int(owner.start_ea)))
        arity = 2 if platform == 'windows' else 3
        for index, item in enumerate(code):
            if item['mnem'] != 'call' or body_target(item['ea']) is None:
                continue
            arguments = recover_call_arguments(code, index, arity)
            callback, name = arguments[-2:]
            if name == literal and isinstance(callback, int) and is_code_address(callback):
                factories.add(callback)
    if len(factories) != 1:
        raise ValueError('VClientVGUI001 registered factory is absent or ambiguous')
    factory = next(iter(factories))
    factory_entries = linear_entries(factory) if platform == 'windows' else scan(factory)
    factory_code = ((linear_instructions(factory_entries) or []) if platform == 'windows'
                    else decoded_calls(factory, factory_entries)) if factory_entries else []
    interface = constant_factory_return(factory_code)
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

    bodies = {}

    def owner_at(site, tail_target=None):
        if platform == 'windows':
            entries = recover_linear_owner(site, tail_target)
            if entries:
                entry = entries[0]['ea']
                bodies[entry] = entries
                return entry
        owner = ida_funcs.get_func(site)
        return int(owner.start_ea) if owner is not None else None

    owners = set()
    for address in (primary, primary-8) if platform == 'linux' else (primary,):
        for ref in idautils.XrefsTo(address, 0):
            if is_code_address(int(ref.frm)):
                owner = owner_at(int(ref.frm))
                if owner is not None:
                    owners.add(owner)
    if platform == 'windows':
        # CZDS 8684 also has decoded constructor instructions without a function
        # or vptr xref. Recover only an actual MOV of the current RTTI address
        # point and its return-delimited callable body without changing the IDB.
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
                        owner = owner_at(site)
                        if owner is not None:
                            owners.add(owner)
                index += 1
    cache = {}

    def flow(owner, entry_state=None):
        if entry_state is None and owner in cache:
            return cache[owner]
        if owner in bodies:
            instructions = linear_instructions(bodies[owner])
            result = (trace_function([dict(start=owner, succs=[], insns=instructions)], owner,
                                     platform, entry_state=entry_state)
                      if instructions else {'stores': [], 'calls': []})
        else:
            result = flow_at(owner, platform, entry_state=entry_state)
        if entry_state is None:
            cache[owner] = result
        return result

    evidence = set()

    def accept(initializer, stores):
        base = unique_constructed_base(interface, primary, stores, secondary_offset)
        if base is None or not is_writable_data(base):
            return
        for entry in bodies.get(initializer) or scan(initializer) or []:
            offset = int(entry['disp'])
            raw = ida_bytes.get_bytes(entry['ea'], entry['len']) or b''
            if (offset and offset+WORD_SIZE <= len(raw)
                    and int.from_bytes(raw[offset:offset+WORD_SIZE], 'little') == base):
                evidence.add((base, initializer, entry['ea'], entry['len'], offset))

    for owner in sorted(owners):
        accept(owner, flow(owner)['stores'])
        for ref in idautils.CodeRefsTo(owner, 0):
            if body_target(int(ref)) != owner:
                continue
            caller = owner_at(int(ref), tail_target=owner)
            if caller is None:
                continue
            caller_ea = caller
            calls = [call for call in flow(caller_ea)['calls'] if call['ea'] == int(ref)]
            if len(calls) != 1:
                continue
            call = calls[0]
            receiver = call['registers'].get('ecx') if platform == 'windows' else call['stack_args'][0]
            if receiver and receiver[0] == 'const' and is_writable_data(receiver[1]):
                constructed = flow(owner, entry_state=entry_state_from_call(call))
                accept(caller_ea, constructed['stores'])
    bases = {item[0] for item in evidence}
    if len(bases) != 1:
        raise ValueError('complete viewport object has no unique constructor/factory proof')
    accesses = []
    for base, owner, site, length, displacement in sorted(evidence):
        function = ida_funcs.get_func(site)
        signature_owner = (hex(int(function.start_ea)) if function is not None
                           and function.start_ea <= site < site + length <= function.end_ea else None)
        accesses.append({'base': hex(base), 'owner': hex(owner), 'site': hex(site),
                         'signature_owner': signature_owner,
                         'body_end': hex(bodies[owner][-1]['next_ea']) if owner in bodies else None,
                         'length': length, 'displacement': displacement})
    return {'pointer_size': WORD_SIZE, 'factory': hex(factory), 'interface': hex(interface),
            'primary_table': hex(primary), 'base': hex(next(iter(bases))), 'accesses': accesses}


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
        signature_owner = item["signature_owner"]
        # An access at a proved logical entry must produce the same signature
        # whether IDA defines it as its own function or folds it into a neighbor.
        entry_access = item["body_end"] is not None and item["site"] == item["owner"]
        function = (
            await inspect_unique_function(session, class_name, int(signature_owner, 0), image_base, debug)
            if not entry_access
            and signature_owner is not None
            and (item["body_end"] is None or signature_owner == item["owner"])
            else None
        )
        if function is not None:
            owner_ea = int(function["func_va"], 0)
            owner = {
                "owner_ea": owner_ea,
                "owner_end": owner_ea + int(function["func_size"], 0),
                "function": function,
                "allow_across": bool(function.get("func_sig_allow_across_function_boundary")),
            }
        elif item["body_end"] is not None:
            # The body and operand are already proved. Generate a unique access
            # signature without making this logical entry an IDA function.
            site = int(item["site"], 0)
            signature = await run_signature(session, site)
            if signature is None:
                continue
            owner = {
                "owner_ea": site,
                "owner_end": int(item["body_end"], 0),
                "function": {"func_va": hex(site), "func_sig": signature["patch_sig"]},
                "allow_across": site + len(signature["patch_sig"].split()) > int(item["body_end"], 0),
            }
        else:
            continue
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
