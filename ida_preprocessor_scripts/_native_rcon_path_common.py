"""Current-input string, operand and function-body checks for native RCON calls.

These helpers implement the confirmed Part B derived xrefs. Intermediate storage
addresses are not public GV artifacts. No discovery uses a previous signature,
peer RVA, reference-build field offset, function size or call ordinal.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk
from ida_preprocessor_scripts._native_rcon_common import CALL_GRAPH_PY, preserve_function_identities

PATH_PY = (
    CALL_GRAPH_PY
    + r"""
PAD_BYTES = {0x90, 0xCC}
ORPHAN_BACKTRACK_LIMIT = 512
LITERAL_SEGMENTS = None

def literal_addresses(literal):
    global LITERAL_SEGMENTS
    needle = literal.encode('ascii') + b'\0'
    addresses = set()
    if LITERAL_SEGMENTS is None:
        LITERAL_SEGMENTS = []
        for start in idautils.Segments():
            segment = ida_segment.getseg(start)
            if int(segment.perm) & int(ida_segment.SEGPERM_EXEC) or segment.type==ida_segment.SEG_BSS:
                continue
            data = ida_bytes.get_bytes(segment.start_ea, int(segment.end_ea)-int(segment.start_ea))
            if data is not None:
                LITERAL_SEGMENTS.append((int(segment.start_ea),data))
    for start,data in LITERAL_SEGMENTS:
        offset = data.find(needle)
        while offset >= 0:
            addresses.add(start+offset)
            offset = data.find(needle, offset+1)
    return addresses

def literal_owners(literal):
    owners = set()
    for address in literal_addresses(literal):
        for ref in elf_data_refs_to(address):
            function = ida_funcs.get_func(ref)
            if function is not None and not is_plt(int(function.start_ea)):
                owners.add(int(function.start_ea))
    return owners

def orphan_entry(anchor):
    # A code/data xref proves this instruction, not a nearby callable entry.
    # Only return a decoded span after actual padding terminating the prior body.
    segment = ida_segment.getseg(anchor)
    if segment is None or not is_code_address(anchor):
        return None
    cursor = int(anchor)
    lower = max(int(segment.start_ea), cursor-ORPHAN_BACKTRACK_LIMIT)
    while cursor > lower:
        previous = idc.prev_head(cursor, lower)
        if previous == idaapi.BADADDR:
            return None
        flags = ida_bytes.get_full_flags(previous)
        raw = ida_bytes.get_bytes(previous, cursor-previous)
        if raw and (ida_bytes.is_align(flags) or all(byte in PAD_BYTES for byte in raw)):
            return cursor
        if ida_funcs.get_func(previous) is not None or not ida_bytes.is_code(flags):
            return None
        cursor = int(previous)
    return None

def semantic_calls(start):
    calls = set()
    for target in native_rcon_edges(start):
        function = ida_funcs.get_func(target)
        name = ida_funcs.get_func_name(target)
        if name.startswith('__x86.get_pc_thunk.'):
            continue
        if function is not None and int(function.end_ea)-target <= 4:
            items = list(idautils.FuncItems(target))
            if items and idc.print_insn_mnem(items[-1]) in ('ret', 'retn'):
                continue
        calls.add(target)
    return calls

def all_globals(start):
    return {address for entry in scan(start) or [] for address in entry['targets']}

def global_writes(start):
    return {address for entry in scan(start) or [] for address in entry['written']}

def immediate(entry, operand=1):
    op = entry['insn'].ops[operand]
    return int(op.value)&0xFFFFFFFF if int(op.type)==int(idaapi.o_imm) else None

def operand_width(op):
    return int(ida_ua.get_dtype_size(op.dtype))

def is_zero_byte_store(entry, address=None):
    return (entry['mnem']=='mov' and immediate(entry)==0
            and operand_width(entry['insn'].ops[0])==1
            and len(entry['written'])==1
            and (address is None or address in entry['written']))

def register_values(start):
    # Interpret only the scalar moves needed to distinguish parameter-driven
    # BeginRedirect from inline mode=RD_PACKET and zero-driven EndRedirect.
    registers = {}
    stack_bias = 0
    frame_bias = None
    result = {}
    for entry in scan(start) or []:
        insn, mnemonic = entry['insn'], entry['mnem']
        destination, source = insn.ops[0], insn.ops[1]
        result[entry['ea']] = dict(registers)
        if mnemonic=='push':
            stack_bias -= 4
        elif mnemonic=='pop':
            stack_bias += 4
        elif (mnemonic in ('sub','add') and int(destination.type)==int(idaapi.o_reg)
              and reg4(destination)=='esp' and immediate(entry) is not None):
            stack_bias += (-1 if mnemonic=='sub' else 1)*int(source.value)
        elif (mnemonic=='mov' and int(destination.type)==int(idaapi.o_reg)
              and int(source.type)==int(idaapi.o_reg) and reg4(destination)=='ebp' and reg4(source)=='esp'):
            frame_bias = stack_bias
        if int(destination.type)!=int(idaapi.o_reg):
            continue
        name = reg4(destination)
        value = None
        if mnemonic=='xor' and int(source.type)==int(idaapi.o_reg) and reg4(source)==name:
            value = ('constant',0)
        elif mnemonic=='mov':
            if int(source.type)==int(idaapi.o_imm):
                value = ('constant',int(source.value)&0xFFFFFFFF)
            elif int(source.type)==int(idaapi.o_reg):
                value = registers.get(reg4(source))
            elif int(source.type)==int(idaapi.o_displ):
                base = reg4(source)
                bias = stack_bias if base=='esp' else frame_bias if base=='ebp' else None
                if bias is not None:
                    slot = bias+signed32(source.addr)
                    if slot in (4,8):
                        value = ('argument',(slot-4)//4)
                elif len(entry['targets'])==1:
                    value = ('global',next(iter(entry['targets'])))
            elif int(source.type)==int(idaapi.o_mem) and len(entry['targets'])==1:
                value = ('global',next(iter(entry['targets'])))
        registers.pop(name,None)
        if value is not None:
            registers[name]=value
    return result

def stored_value(entry, register_state):
    value = immediate(entry)
    if value is not None:
        return ('constant',value)
    source = entry['insn'].ops[1]
    return register_state.get(reg4(source)) if int(source.type)==int(idaapi.o_reg) else None

def redirect_storage(flush):
    entries = scan(flush) or []
    buffers = {next(iter(entry['written'])) for entry in entries if is_zero_byte_store(entry)}
    states = register_values(flush)
    modes = set()
    for entry in entries:
        if entry['mnem']!='cmp' or immediate(entry)!=2:
            continue
        operand = entry['insn'].ops[0]
        if int(operand.type)==int(idaapi.o_reg):
            value = states[entry['ea']].get(reg4(operand))
            if value and value[0]=='global':
                modes.add(value[1])
        elif len(entry['targets'])==1 and operand_width(operand)==4:
            modes.update(entry['targets'])
    if len(buffers)!=1 or len(modes)!=1:
        raise ValueError('ambiguous current redirect mode/output operands')
    return next(iter(modes)),next(iter(buffers))

def functions_referencing(address):
    owners=set()
    for candidate in (int(address),int(ida_bytes.get_item_head(address))):
        for ref in elf_data_refs_to(candidate):
            function=ida_funcs.get_func(ref)
            if function is not None and not is_plt(int(function.start_ea)):
                owners.add(int(function.start_ea))
    return owners

def recover_end_redirect(ref, flush, mode):
    if ida_funcs.get_func(ref) is not None:
        return None
    # The unowned source body begins at its sole FlushRedirect call. Validate
    # the complete call/zero-store/RET span before materializing its boundary.
    if orphan_entry(ref)!=int(ref) or local_call_target(ref)!=flush:
        return None
    cursor=int(ref)
    items=[]
    while len(items)<8:
        insn=ida_ua.insn_t()
        size=ida_ua.decode_insn(insn,cursor)
        if not size or not is_code_address(cursor):
            return None
        items.append(cursor)
        mnemonic=(idc.print_insn_mnem(cursor) or '').lower()
        cursor+=int(size)
        if mnemonic in ('ret','retn'):
            break
        if len(items)>1 and mnemonic!='mov':
            return None
    if len(items)!=3 or idc.print_insn_mnem(items[-1]) not in ('ret','retn'):
        return None
    store=ida_ua.insn_t()
    ida_ua.decode_insn(store,items[1])
    if (int(store.ops[0].type)!=int(idaapi.o_mem) or int(store.ops[0].addr)!=mode
            or int(store.ops[1].type)!=int(idaapi.o_imm) or int(store.ops[1].value)!=0
            or operand_width(store.ops[0])!=4):
        return None
    if not ida_funcs.add_func(ref,cursor):
        return None
    return int(ref)

def return_boolean_body(start):
    entries=scan(start) or []
    one=any(entry['mnem']=='mov' and int(entry['insn'].ops[0].type)==int(idaapi.o_reg)
            and reg4(entry['insn'].ops[0])=='eax'
            and immediate(entry)==1 for entry in entries)
    zero=any(entry['mnem']=='xor' and int(entry['insn'].ops[0].type)==int(idaapi.o_reg)
             and int(entry['insn'].ops[1].type)==int(idaapi.o_reg) and reg4(entry['insn'].ops[0])=='eax'
             and reg4(entry['insn'].ops[1])=='eax' for entry in entries)
    return one and zero

def shared_storage(left,right):
    # Candidate generation includes the record base and its initial Boolean
    # fields. Final acceptance also requires the same address-comparison call,
    # a read-only loop and true/false exits; proximity alone never identifies it.
    return any(abs(a-b)<=8 for a in left for b in right)

def float_globals(start):
    found=set()
    scalar_mnemonics={'fld','movss','comiss','ucomiss','cvttss2si','cvtss2si'}
    for entry in scan(start) or []:
        if entry['mnem'] not in scalar_mnemonics:
            continue
        if any(operand_width(op)==4 and int(op.type) in (int(idaapi.o_mem),int(idaapi.o_displ))
               for op in entry['insn'].ops):
            found.update(entry['targets']-entry['written'])
    return found
"""
)


async def write_path_functions(session, expected_outputs, new_binary_dir, platform, image_base, located):
    """Generate signatures only after the confirmed locator returns real entries."""
    if located.get("error") or not isinstance(located.get("functions"), dict):
        return False
    for name, address in located["functions"].items():
        output = _output_for_symbol(expected_outputs, name)
        function = await inspect_func(session, int(address, 0), image_base, name)
        if output is None or function is None:
            return False
        write_func_yaml(output, function)
    return await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, list(located["functions"])
    )


async def locate_path_functions(session, body, values):
    return await run_walk(session, PATH_PY + body, values)
