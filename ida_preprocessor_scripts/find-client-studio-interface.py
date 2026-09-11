#!/usr/bin/env python3
"""Recover the client renderer through its returned public studio interface.

The returned version-1 table owns the two thunks. Their common this object and
its explicit vptr initialization identify the renderer, including builds whose
virtual calls were devirtualized. No compiler-specific vtable index is assumed.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    parse_mcp_result,
    write_func_yaml,
    write_gv_yaml,
    write_vtable_yaml,
)

LOCATE = r'''
import ida_bytes, ida_funcs, ida_gdl, ida_segment, ida_ua, idaapi, idautils, idc, json
export_ea = EXPORT_EA
target_platform = TARGET_PLATFORM

def mapped(ea):
    return 0 <= int(ea) <= 0xFFFFFFFF and ida_segment.getseg(int(ea)) is not None

def data(ea):
    seg = ida_segment.getseg(int(ea)) if mapped(ea) else None
    return seg is not None and not (seg.perm & ida_segment.SEGPERM_EXEC)

def function(ea):
    f = ida_funcs.get_func(int(ea)) if mapped(ea) else None
    # Some builds leave constructor and vtable-only entries as unowned code.
    # Materialize only an existing instruction head in an executable segment.
    if f is None and mapped(ea):
        seg = ida_segment.getseg(int(ea))
        flags = ida_bytes.get_full_flags(int(ea))
        if seg.perm & ida_segment.SEGPERM_EXEC and ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            ida_funcs.add_func(int(ea))
            f = ida_funcs.get_func(int(ea))
    return f is not None and f.start_ea == ea

def refs(ea):
    found = {int(x) for x in idautils.DataRefsFrom(ea) if data(x)}
    insn = idautils.DecodeInstruction(ea)
    if insn:
        for op in insn.ops:
            if op.type == ida_ua.o_imm and data(op.value):
                found.add(int(op.value))
            elif op.type == ida_ua.o_mem and data(op.addr):
                found.add(int(op.addr))
    return found

def expand(values):
    found = set(values)
    for value in values:
        indirect = ida_bytes.get_dword(value)
        if data(indirect):
            found.add(int(indirect))
    return found

def body(ea):
    return list(idautils.FuncItems(int(ea)))

def table_entries(ea):
    entries = []
    while data(ea + len(entries) * 4):
        target = ida_bytes.get_dword(ea + len(entries) * 4)
        if not function(target):
            break
        entries.append(int(target))
    return entries

def register_source(ea, register):
    owner = ida_funcs.get_func(ea)
    block = next((b for b in ida_gdl.FlowChart(owner) if b.start_ea <= ea < b.end_ea), None)
    if block is None:
        return set()
    instructions = list(idautils.Heads(block.start_ea, ea))
    for previous in reversed(instructions):
        mnemonic = idc.print_insn_mnem(previous).lower()
        if mnemonic == 'call' and register in ('eax', 'ecx', 'edx'):
            return set()
        if idc.print_operand(previous, 0).lower() == register:
            if mnemonic in ('mov', 'lea'):
                return expand(refs(previous))
            return set()
    return set()

def dispatch(ea):
    direct = set()
    slots = set()
    accesses = []
    for insn_ea in body(ea):
        insn = idautils.DecodeInstruction(insn_ea)
        if not insn:
            continue
        for target in expand(refs(insn_ea)):
            seg = ida_segment.getseg(target)
            if seg and seg.perm & ida_segment.SEGPERM_WRITE:
                accesses.append((target, int(insn_ea)))
        if idc.print_insn_mnem(insn_ea).lower() not in ('call', 'jmp'):
            continue
        op = insn.ops[0]
        if op.type == ida_ua.o_near and function(op.addr) and op.addr != ea:
            items = body(op.addr)
            # GCC's PC thunk only materializes the return address, not dispatch.
            if len(items) == 2 and idc.print_insn_mnem(items[0]) == 'mov' and idc.print_operand(items[0], 1) == '[esp]' and idc.print_insn_mnem(items[1]) == 'retn':
                continue
            direct.add(int(op.addr))
        elif op.type in (ida_ua.o_displ, ida_ua.o_phrase):
            offset = int(op.addr) if op.type == ida_ua.o_displ else 0
            if offset >= 0 and offset % 4 == 0:
                slots.add(offset // 4)
    return direct, slots, accesses

def linear_body(start):
    """Walk only explicit straight-line edges, including compiler jump thunks."""
    cursor = int(start)
    visited = set()
    for _ in range(256):
        if cursor in visited or not mapped(cursor):
            return
        visited.add(cursor)
        insn = idautils.DecodeInstruction(cursor)
        if not insn:
            return
        mnemonic = idc.print_insn_mnem(cursor).lower()
        if mnemonic == 'jmp' and insn.ops[0].type == ida_ua.o_near:
            cursor = int(insn.ops[0].addr)
            continue
        yield cursor
        if mnemonic.startswith('ret') or mnemonic.startswith('j'):
            return
        cursor += insn.size

def returns_msvc_this(target):
    aliases = {'ecx'}
    for ea in linear_body(target):
        insn = idautils.DecodeInstruction(ea)
        mnemonic = idc.print_insn_mnem(ea).lower()
        if mnemonic.startswith('ret'):
            return 'eax' in aliases
        if mnemonic == 'call':
            aliases.difference_update({'eax', 'ecx', 'edx'})
        elif insn.ops[0].type == ida_ua.o_reg and mnemonic not in ('push', 'cmp', 'test'):
            dest = idc.print_operand(ea, 0).lower()
            source_is_this = mnemonic == 'mov' and idc.print_operand(ea, 1).lower() in aliases
            aliases.discard(dest)
            if source_is_this:
                aliases.add(dest)
    return False

def constructor_tables(object_access, obj):
    # Follow the explicit ABI this argument to its next direct call. This is
    # a def-use chain, not a fixed offset from the global initializer.
    first = idautils.DecodeInstruction(object_access)
    if not first:
        return set()
    mnemonic = idc.print_insn_mnem(object_access).lower()
    dest_text = idc.print_operand(object_access, 0).lower()
    msvc_this = mnemonic == 'mov' and dest_text == 'ecx'
    stack_this = (mnemonic == 'push' or (mnemonic == 'mov' and first.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ) and first.ops[0].addr == 0 and '[esp' in dest_text))
    if not (msvc_this or stack_this):
        return set()
    if obj not in refs(object_access):
        return set()
    cursor = object_access
    target = None
    for _ in range(32):
        cursor = idc.next_head(cursor)
        insn = idautils.DecodeInstruction(cursor)
        if not insn:
            return set()
        mnemonic = idc.print_insn_mnem(cursor).lower()
        if mnemonic in ('call', 'jmp'):
            if insn.ops[0].type == ida_ua.o_near:
                target = int(insn.ops[0].addr)
            break
        dest_text = idc.print_operand(cursor, 0).lower()
        if mnemonic.startswith('j') or mnemonic.startswith('ret') or (msvc_this and dest_text == 'ecx'):
            return set()
        if stack_this and (mnemonic in ('push', 'pop') or dest_text == 'esp' or (insn.ops[0].type in (ida_ua.o_phrase, ida_ua.o_displ) and insn.ops[0].addr == 0 and '[esp' in dest_text)):
            return set()
    if target is None or not mapped(target) or not ida_bytes.is_code(ida_bytes.get_full_flags(target)):
        return set()
    if idc.print_insn_mnem(cursor).lower() == 'call':
        # The caller may complete an inlined derived constructor after a base
        # constructor call. Its subsequent explicit store supersedes that table.
        for later in linear_body(cursor + idautils.DecodeInstruction(cursor).size):
            following = idautils.DecodeInstruction(later)
            mnemonic = idc.print_insn_mnem(later).lower()
            if mnemonic == 'call' or mnemonic.startswith('ret'):
                break
            if mnemonic == 'mov' and following.ops[0].type == ida_ua.o_mem and following.ops[0].addr == obj:
                return set()
    aliases = {'ecx'} if msvc_this else set()
    stack_delta = 0
    frame_delta = None
    tables = set()
    for cursor in linear_body(target):
        insn = idautils.DecodeInstruction(cursor)
        if not insn:
            break
        mnemonic = idc.print_insn_mnem(cursor).lower()
        if mnemonic.startswith('ret'):
            # A destructor can also overwrite the vptr with a base table.
            # Constructors in this ABI return the original this in eax.
            return tables if stack_this or 'eax' in aliases else set()
        if mnemonic.startswith('j'):
            break
        dest, source = insn.ops[0], insn.ops[1]
        dest_name = idc.print_operand(cursor, 0).lower()
        source_name = idc.print_operand(cursor, 1).lower()
        if mnemonic == 'mov':
            if dest.type in (ida_ua.o_phrase, ida_ua.o_displ) and dest.addr == 0 and source.type == ida_ua.o_imm:
                operand = idc.print_operand(cursor, 0).lower().replace('dword ptr ', '')
                if operand in {'[' + register + ']' for register in aliases} and data(source.value):
                    tables.add(int(source.value))
            if dest.type == ida_ua.o_reg:
                source_is_this = source.type == ida_ua.o_reg and source_name in aliases
                if stack_this and source.type == ida_ua.o_displ:
                    if '[esp' in source_name and int(source.addr) == 4 - stack_delta:
                        source_is_this = True
                    elif frame_delta is not None and '[ebp' in source_name and int(source.addr) == 4 - frame_delta:
                        source_is_this = True
                aliases.discard(dest_name)
                if source_is_this:
                    aliases.add(dest_name)
                if dest_name == 'ebp' and source_name == 'esp':
                    frame_delta = stack_delta
        elif mnemonic == 'call':
            returns_this = 'ecx' in aliases and dest.type == ida_ua.o_near and returns_msvc_this(int(dest.addr))
            aliases.difference_update({'eax', 'ecx', 'edx'})
            if returns_this:
                aliases.add('eax')
        elif dest.type == ida_ua.o_reg and mnemonic not in ('push', 'cmp', 'test'):
            aliases.discard(idc.print_operand(cursor, 0).lower())
        if mnemonic == 'push':
            stack_delta -= 4
        elif mnemonic == 'pop':
            stack_delta += 4
        elif dest_name == 'esp' and source.type == ida_ua.o_imm:
            if mnemonic == 'sub':
                stack_delta -= int(source.value)
            elif mnemonic == 'add':
                stack_delta += int(source.value)
    return set()

def main():
    if idaapi.inf_is_64bit() or not function(export_ea):
        raise ValueError('expected x86 exported function start')
    candidates = set()
    for ea in body(export_ea):
        for address in expand(refs(ea)):
            if ida_bytes.get_dword(address) == 1 and function(ida_bytes.get_dword(address + 4)) and function(ida_bytes.get_dword(address + 8)):
                candidates.add(address)
    if len(candidates) != 1:
        raise ValueError('returned studio interface table is not unique: ' + repr(candidates))
    studio = candidates.pop()
    thunks = [ida_bytes.get_dword(studio + 4), ida_bytes.get_dword(studio + 8)]
    dispatches = [dispatch(ea) for ea in thunks]
    shared_objects = set(x[0] for x in dispatches[0][2]) & set(x[0] for x in dispatches[1][2])
    resolved = []
    evidence = []
    for obj in shared_objects:
        vtables = set()
        if data(ida_bytes.get_dword(obj)):
            vtables.add(int(ida_bytes.get_dword(obj)))
        for xref in idautils.XrefsTo(obj):
            ea = int(xref.frm)
            vtables.update(constructor_tables(ea, obj))
            insn = idautils.DecodeInstruction(ea)
            if not insn or idc.print_insn_mnem(ea).lower() != 'mov':
                continue
            dest, source = insn.ops[0], insn.ops[1]
            if dest.type not in (ida_ua.o_mem, ida_ua.o_displ) or obj not in refs(ea):
                continue
            if dest.type == ida_ua.o_mem and dest.addr != obj:
                continue
            if source.type == ida_ua.o_imm:
                vtables.add(int(source.value))
            elif source.type == ida_ua.o_reg:
                vtables.update(register_source(ea, idc.print_operand(ea, 1).lower()))
        for table in vtables:
            entries = table_entries(table)
            evidence.append((hex(obj), hex(table), len(entries), sorted(dispatches[0][0]), sorted(dispatches[1][0]), sorted(dispatches[1][1])))
            model_direct, model_slots, _ = dispatches[0]
            matching = {i for i, target in enumerate(entries) if target in model_direct} | {i for i in model_slots if i < len(entries)}
            if len(matching) != 1:
                continue
            model_index = matching.pop()
            # The player thunk may inline its outer method. Its common this
            # object still establishes ownership, while DrawModel's dead-player
            # branch supplies the downstream semantic locator for DrawPlayer.
            access = next(ea for target, ea in dispatches[1][2] if target == obj)
            decoded = idautils.DecodeInstruction(access)
            offb = next((int(op.offb) for op in decoded.ops if op.offb), 0)
            if offb:
                resolved.append({'object': obj, 'table': table, 'entries': entries, 'indices': [model_index], 'thunks': thunks, 'object_insn': access, 'object_insn_size': decoded.size, 'object_disp': offb})
    if len(resolved) > 1 and target_platform == 'linux':
        # Itanium single-inheritance RTTI links a derived class to its base.
        # A destructor can install the base vptr on the same singleton; retain
        # the derived table only when the actual RTTI proves that relationship.
        def derives(child, parent):
            child_type = ida_bytes.get_dword(child['table'] - 4)
            parent_type = ida_bytes.get_dword(parent['table'] - 4)
            return (child['object'] == parent['object'] and child_type != parent_type
                    and data(child_type) and data(parent_type)
                    and ida_bytes.get_dword(child_type + 8) == parent_type)
        resolved = [candidate for candidate in resolved if not any(derives(other, candidate) for other in resolved)]
    if len(resolved) != 1:
        raise ValueError('renderer object/vptr/dispatch relation is not unique: ' + repr({'resolved': resolved, 'tables': evidence, 'objects': sorted(shared_objects)}))
    return {'pointer_size': 4, **resolved[0]}

globals().update(locals())
try:
    result = json.dumps(main())
except Exception as exc:
    result = json.dumps({'error': str(exc)})
'''


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
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"HUD_GetStudioModelInterface.{platform}.yaml")
    if not owner:
        return False
    code = LOCATE.replace("EXPORT_EA", str(int(owner["func_va"], 0))).replace("TARGET_PLATFORM", repr(platform))
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(located, dict) or located.get("pointer_size") != 4:
        if debug:
            print(f"  client studio interface: {located}")
        return False
    names = ["GameStudioRenderer_StudioDrawModel"]
    payloads = {}
    for name, index in zip(names, located["indices"]):
        function = await _inspect_function_via_mcp(session, located["entries"][index], image_base, name)
        model_allow_across = not function or not function.get("func_sig")
        if model_allow_across:
            function = await _inspect_function_via_mcp(
                session,
                located["entries"][index],
                image_base,
                name,
                allow_across_function_boundary=True,
            )
        if not function or not function.get("func_sig"):
            return False
        payloads[name] = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size")}
        payloads[name].update(
            vtable_name="GameStudioRenderer",
            vfunc_index=index,
            vfunc_offset=hex(index * 4),
            vfunc_sig=function["func_sig"],
        )
        if model_allow_across:
            payloads[name]["vfunc_sig_allow_across_function_boundary"] = True
    thunk = await _inspect_function_via_mcp(session, located["thunks"][1], image_base, "ClientStudioDrawPlayer")
    allow_across = not thunk or not thunk.get("func_sig")
    if allow_across:
        thunk = await _inspect_function_via_mcp(
            session, located["thunks"][1], image_base, "ClientStudioDrawPlayer", allow_across_function_boundary=True
        )
    if not thunk or not thunk.get("func_sig"):
        return False
    gv = {
        "gv_name": "g_pGameStudioRenderer",
        "gv_va": hex(located["object"]),
        "gv_rva": hex(located["object"] - image_base),
        "gv_sig": thunk["func_sig"],
        "gv_sig_va": thunk["func_va"],
        "gv_inst_offset": located["object_insn"] - located["thunks"][1],
        "gv_inst_length": located["object_insn_size"],
        "gv_inst_disp": located["object_disp"],
    }
    if allow_across:
        gv["gv_sig_allow_across_function_boundary"] = True
    metadata = await gv_resolution_fields_via_mcp(
        session, located["object_insn"], located["object_disp"], located["object"], image_base, platform
    )
    if metadata is None:
        return False
    gv.update(metadata)
    table = {
        "vtable_class": "GameStudioRenderer",
        "vtable_symbol": "GameStudioRenderer",
        "vtable_va": hex(located["table"]),
        "vtable_rva": hex(located["table"] - image_base),
        "vtable_size": hex(len(located["entries"]) * 4),
        "vtable_numvfunc": len(located["entries"]),
        "vtable_entries": {i: hex(ea) for i, ea in enumerate(located["entries"])},
    }
    outputs = {
        name: _output_for_symbol(expected_outputs, name)
        for name in [*names, "g_pGameStudioRenderer", "GameStudioRenderer_vtable"]
    }
    if not all(outputs.values()):
        return False
    for name, payload in payloads.items():
        write_func_yaml(outputs[name], payload)
    write_gv_yaml(outputs["g_pGameStudioRenderer"], gv)
    write_vtable_yaml(outputs["GameStudioRenderer_vtable"], table)
    return True
