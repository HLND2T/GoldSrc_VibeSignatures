#!/usr/bin/env python3
"""Locate SvEngine's Linux network thread from its creation failure literal.

Both Sven ELF32 builds reference the exact failure string from NET_StartThread
and an inline queue initializer. Validate all creation paths, require agreement,
and select only the minimal standalone body. No ELF symbol name, old artifact,
fixed call ordinal or generated signature participates in target discovery.

pthread_create(&netThread, NULL, NET_ThreadFunc, NULL) outputs pthread_t to
netThread; its EAX error code is stored in netThreadId. Both GV artifacts denote
storage addresses, not runtime values or a kernel TID. PIC operands use the
shared GOT decoder and artifact resolution fields; Windows rules do not apply.
"""

import inspect

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts import x86_call_arguments
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import func_payload, inspect_func, owner_context, run_walk

NAMES = ("NET_StartThread", "NET_ThreadFunc", "netThread", "netThreadId")
LITERAL = "Couldn't initialize network thread, run with -nonetthread\n"

WALK = (
    inspect.getsource(x86_call_arguments)
    + r"""
import ida_frame

APIS = {'pthread_create', 'pthread_mutex_destroy'}
imports = {}
def collect_import(ea, name, ordinal):
    name = name.split('@')[0] if name else None
    if name and name in APIS: imports[int(ea)] = name
    return True
for index in range(ida_nalt.get_import_module_qty()):
    ida_nalt.enum_import_names(index, collect_import)

def api_name(site):
    target = int(idc.get_operand_value(site, 0))
    for _ in range(4):
        if target in imports: return imports[target]
        insn = idautils.DecodeInstruction(target)
        if insn is None or insn.get_canon_mnem().lower() != 'jmp': return None
        op = insn.ops[0]
        if op.type == idaapi.o_near: target = int(op.addr)
        elif op.type == idaapi.o_mem: target = int(ida_bytes.get_dword(op.addr))
        else:
            slots = [int(ref) for ref in idautils.DataRefsFrom(target) if is_got(ref)]
            if len(slots) != 1: return None
            target = int(ida_bytes.get_dword(slots[0]))
    return None

def unindexed(op):
    return not op.specflag1 or ((int(op.specflag2) >> 3) & 7) == 4

def address_operand(entry, op, base, register):
    kind = int(op.type)
    if kind == idaapi.o_imm: value = int(op.value)
    elif kind == idaapi.o_mem: value = int(op.addr)
    elif (kind == idaapi.o_displ and reg4(op) == register and unindexed(op)
          and base is not None): value = (base + signed32(op.addr)) & 0xFFFFFFFF
    else: return None
    offset = int(op.offb)
    if not offset or offset + WORD > entry['len']: return None
    # Keep the instruction carrying the address, including its PIC displacement.
    return ('address', value, entry['ea'], offset, entry['len'])

def encode(entry, op, sp):
    if op.type == idaapi.o_reg: return ('reg', reg4(op))
    if op.type in (idaapi.o_imm, idaapi.o_near):
        return ('imm', int(op.value) if op.type == idaapi.o_imm else int(op.addr))
    if op.type in (idaapi.o_displ, idaapi.o_phrase) and reg4(op) == 'esp' and unindexed(op):
        if ida_ua.get_dtype_size(op.dtype) != WORD: return ('unknown', None)
        return ('stack', sp + signed32(op.addr))
    # An ordinary memory load is not an address-of expression.
    return ('unknown', None)

def region_code(entries, index, owner):
    first = index
    while first:
        previous = entries[first-1]
        if (previous['ea'] + previous['len'] != entries[first]['ea']
                or previous['mnem'] == 'call' or previous['mnem'].startswith('j')
                or previous['mnem'].startswith('ret')): break
        first -= 1
    region = entries[first:index+1]
    addresses = {e['ea'] for e in region}
    if any(int(ref) not in addresses for e in region[1:] for ref in idautils.CodeRefsTo(e['ea'], False)):
        return None
    base, register = got_anchor(int(owner.start_ea))
    code = []
    for entry in region:
        sp = int(ida_frame.get_spd(owner, entry['ea']))
        insn, mnemonic = entry['insn'], entry['mnem']
        ops = [encode(entry, op, sp) for op in insn.ops if op.type != idaapi.o_void]
        if mnemonic == 'lea':
            tagged = address_operand(entry, insn.ops[1], base, register)
            ops[1] = ('imm', tagged) if tagged else ('unknown', None)
            mnemonic = 'mov'
        elif mnemonic == 'push' and insn.ops[0].type == idaapi.o_imm:
            tagged = address_operand(entry, insn.ops[0], base, register)
            if tagged: ops[0] = ('imm', tagged)
        code.append({'ea':entry['ea'], 'mnem':mnemonic, 'ops':ops, 'sp':sp})
    return code

def call_args(entries, index, owner, arity):
    code = region_code(entries, index, owner)
    return recover_call_arguments(code, len(code)-1, arity) if code else None

def stored_constant(entries, index, owner):
    code = region_code(entries, index, owner)
    if not code or entries[index]['mnem'] != 'mov': return None
    # Read the source's reaching definition through the shared argument engine.
    code[-1] = dict(code[-1], ops=[('stack', 0), code[-1]['ops'][1]])
    code.append({'ea':entries[index]['ea']+entries[index]['len'], 'mnem':'call', 'ops':[], 'sp':0})
    return recover_call_arguments(code, len(code)-1, 1)[0]

def value(arg):
    return arg[1] if isinstance(arg, tuple) and arg[0] == 'address' else arg

def writable_word(ea):
    seg = ida_segment.getseg(ea)
    return bool(is_writable_data(ea) and not is_got(ea) and ea % WORD == 0 and ea + WORD <= seg.end_ea)

def word_register(op, name):
    return op.type == idaapi.o_reg and ida_ua.get_dtype_size(op.dtype) == WORD and reg4(op) == name

def inspect_path(start, literal):
    owner = ida_funcs.get_func(start)
    entries = scan(start)
    if not owner or not entries: return None
    calls = []
    for index, entry in enumerate(entries):
        if entry['mnem'] != 'call': continue
        name = api_name(entry['ea'])
        target = local_call_target(entry['ea'])
        args = call_args(entries, index, owner, 4 if name == 'pthread_create' else 1)
        calls.append({'index':index, 'ea':entry['ea'], 'name':name, 'target':target, 'args':args})
    creates = [c for c in calls if c['name'] == 'pthread_create']
    destroys = [c for c in calls if c['name'] == 'pthread_mutex_destroy']
    fatals = [c for c in calls if c['target'] == int(values['fatal']) and c['args']
              and value(c['args'][0]) == literal]
    if len(creates) != 1 or len(destroys) != 1 or len(fatals) != 1: return None
    create, destroy, fatal = creates[0], destroys[0], fatals[0]
    args = create['args']
    if not args or args[1] != 0 or args[3] != 0: return None
    output, callback = args[0], args[2]
    if not all(isinstance(a, tuple) and a[0] == 'address' for a in (output, callback)): return None
    thread, routine = value(output), value(callback)
    function = ida_funcs.get_func(routine)
    if (not writable_word(thread) or not is_code_address(routine) or not function
            or int(function.start_ea) != routine or is_plt(routine)): return None
    if not destroy['args'] or not writable_word(value(destroy['args'][0])): return None
    mutex = value(destroy['args'][0])
    stores = []
    for index, entry in enumerate(entries):
        if entry['mnem'] == 'mov' and entry['written']:
            if len(entry['written']) != 1 or ida_ua.get_dtype_size(entry['insn'].ops[0].dtype) != WORD:
                return None
            gv = next(iter(entry['written']))
            stores.append((index, gv, stored_constant(entries,index,owner), entry))
    result_stores = [(i,gv,e) for i,gv,v,e in stores
                     if create['ea'] < e['ea'] < destroy['ea']
                     and word_register(e['insn'].ops[1],'eax')]
    if len(result_stores) != 1: return None
    result_index, error_code, result_store = result_stores[0]
    if not writable_word(error_code) or error_code == thread: return None
    resets = [(i,gv,e) for i,gv,v,e in stores if destroy['ea'] < e['ea'] < fatal['ea'] and v == 0]
    rollback = {gv for i,gv,e in resets}
    initialized = [(i,gv,e) for i,gv,v,e in stores if e['ea'] < create['ea'] and v == 1 and gv in rollback]
    if len(rollback) != 2 or len(resets) != 2 or len(initialized) != 1 or {thread,error_code,mutex} & rollback:
        return None
    # TEST EAX,EAX can precede or follow the result store. MOV preserves flags.
    guards = []
    for index in range(create['index']+1, destroy['index']):
        entry = entries[index]
        ops = entry['insn'].ops
        if entry['mnem'] != 'test' or not all(word_register(op,'eax') for op in (ops[0],ops[1])):
            continue
        following = index + 1
        while following < destroy['index'] and entries[following]['mnem'] == 'mov':
            destination = entries[following]['insn'].ops[0]
            if destination.type == idaapi.o_reg and reg4(destination) == 'eax': break
            following += 1
        if following < destroy['index'] and entries[following]['mnem'] in ('jnz','jne'):
            guards.append(following)
    if len(guards) != 1: return None
    successors = decode_function_flow(owner, [e['ea'] for e in entries])
    graph = _control_flow([dict(e, successors=successors[e['ea']]) for e in entries])
    guard = guards[0]
    taken = next((i for i,e in enumerate(entries) if e['ea'] == int(entries[guard]['insn'].ops[0].addr)), None)
    if taken is None or not _may_reach(graph,taken,fatal['index']): return None
    if _may_reach(graph,guard+1,destroy['index']): return None
    required = [create['index'],result_index,guard,destroy['index'],initialized[0][0],*[i for i,gv,e in resets]]
    if any(_may_reach(graph,0,fatal['index'],blocked=i) for i in required): return None
    # Do not let a clobbered EAX masquerade as pthread_create's return value.
    if any(e['mnem'] not in ('mov','test','jnz','jne') or
           (e['insn'].ops[0].type == idaapi.o_reg and changed_operand(e['insn'],0))
           for e in entries[create['index']+1:guard]): return None
    pre_reads = set().union(*(e['targets'] - e['written'] for e in entries[:initialized[0][0]]))
    if not rollback <= pre_reads: return None
    # Both state loads must really guard creation: use_thread == 0 and
    # initialized != 0 skip it. A nearby read alone is insufficient evidence.
    for gv in rollback:
        branches = ('jnz','jne') if gv == initialized[0][1] else ('jz','je')
        matches = []
        for i,e in enumerate(entries[:initialized[0][0]-2]):
            if e['mnem'] != 'mov' or e['targets'] != {gv} or e['written'] or e['insn'].ops[0].type != idaapi.o_reg:
                continue
            test, branch = entries[i+1:i+3]
            reg = reg4(e['insn'].ops[0])
            if test['mnem'] != 'test' or not all(word_register(op,reg) for op in (test['insn'].ops[0],test['insn'].ops[1])):
                continue
            if branch['mnem'] not in branches: continue
            destination = next((j for j,x in enumerate(entries) if x['ea'] == int(branch['insn'].ops[0].addr)),None)
            if (destination is None or _may_reach(graph,destination,create['index'])
                    or not _may_reach(graph,i+3,create['index'])
                    or _may_reach(graph,0,create['index'],blocked=i+2)): continue
            matches.append(i+2)
        if len(matches) != 1: return None
    base, register = got_anchor(start)
    allowed = True
    for c in calls:
        if c in (create,destroy,fatal): continue
        # A verified get-PC thunk is compiler setup, not network work.
        if base is not None and c['index']+1 < len(entries):
            following = entries[c['index']+1]
            if following['mnem'] == 'add' and reg4(following['insn'].ops[0]) == register:
                thunk = list(idautils.FuncItems(c['target'])) if c['target'] else []
                if len(thunk) == 2 and idc.print_insn_mnem(thunk[0]) == 'mov' and idc.print_insn_mnem(thunk[1]).startswith('ret'):
                    continue
        arg = value(c['args'][0]) if c['args'] else None
        text = ida_bytes.get_strlit_contents(arg,-1,0) if isinstance(arg,int) else None
        if not text or not text.startswith(b'Threaded networking '): allowed = False
    other_writes = any(e['insn'].ops[0].type in (idaapi.o_mem,idaapi.o_displ,idaapi.o_phrase)
                       and changed_operand(e['insn'],0) and not e['written']
                       and reg4(e['insn'].ops[0]) != 'esp' for e in entries)
    return {'start':start, 'routine':routine, 'thread':access({'ea':output[2],'len':output[4],'disp':output[3],'disasm':idc.generate_disasm_line(output[2],0)},thread),
            'error_code':access(result_store,error_code), 'create':create['ea'], 'destroy':destroy['ea'],
            'fatal':fatal['ea'], 'mutex':mutex, 'standalone':allowed and not other_writes and {gv for i,gv,v,e in stores} == rollback | {error_code}}

def locate():
    if idaapi.inf_is_64bit(): return {'error':'expected ELF32 x86'}
    strings = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if seg.perm & ida_segment.SEGPERM_EXEC: continue
        needle = values['literal'].encode() + b'\0'
        cursor = start
        while cursor < seg.end_ea:
            found = ida_bytes.find_bytes(needle,cursor,range_end=seg.end_ea,flags=ida_bytes.BIN_SEARCH_FORWARD|ida_bytes.BIN_SEARCH_NOSHOW)
            if found == idaapi.BADADDR: break
            strings.append(int(found)); cursor = found+len(needle)
    if len(strings) != 1: return {'error':'expected one exact pthread failure literal','strings':strings}
    owners = {int(f.start_ea) for ref in elf_data_refs_to(strings[0]) if (f := ida_funcs.get_func(ref))}
    paths = [p for start in sorted(owners) if (p := inspect_path(start,strings[0]))]
    if not paths or len({(p['routine'],p['thread']['gv_ea'],p['error_code']['gv_ea'],p['mutex']) for p in paths}) != 1:
        return {'error':'pthread creation paths missing or disagree','paths':paths}
    standalone = [p for p in paths if p['standalone']]
    if len(standalone) != 1: return {'error':'expected one standalone NET_StartThread','paths':paths}
    return {'pointer_size':WORD,'literal':hex(strings[0]),'selected':standalone[0],'paths':paths}

result = locate()
"""
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in NAMES}
    if platform != "linux" or any(output is None for output in outputs.values()):
        return False
    fatal = await inspect_owner_artifact(
        session, new_binary_dir, platform, image_base, "Sys_Error", allow_raw_span=True
    )
    if fatal is None:
        return False
    located = await run_walk(session, WALK, {"literal": LITERAL, "fatal": fatal["owner_ea"]})
    if debug:
        print(f"  {skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    path = located["selected"]
    owner = await owner_context(session, path["start"], image_base, "NET_StartThread")
    callback = await inspect_func(session, path["routine"], image_base, "NET_ThreadFunc")
    if owner is None or callback is None:
        return False
    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {"netThread": path["thread"], "netThreadId": path["error_code"]},
    ):
        return False
    write_func_yaml(outputs["NET_StartThread"], func_payload(owner["function"]))
    write_func_yaml(outputs["NET_ThreadFunc"], callback)
    return True
