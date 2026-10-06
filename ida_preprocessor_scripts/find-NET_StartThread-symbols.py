#!/usr/bin/env python3
"""Locate Windows network-thread symbols from the creation-failure diagnostic.

GoldSrc/CoF use ``run without -net_thread``; SvEngine uses ``run with
-nonetthread``. Each exact C string is unique, but Sven keeps inline copies in
NET_Init and the message-queue builder as well as the standalone start routine.
Only the body consisting of the two state guards, critical-section setup,
CreateThread, handle test, rollback and diagnostics is NET_StartThread.
HL25 Windows has only the NET_Init inline path and emits no NET_StartThread.

Some classic IDBs assign the entire callable start body to a queue builder's
tail chunk. Recover that body only after verifying its semantics and sole
incoming tail jump. Sven's unused standalone body is unowned; its preceding
alignment and closed control flow provide boundaries, never a fixed address.

CreateThread's third and sixth arguments are recovered with the shared x86
reaching-definition walker, including operand provenance. The sixth argument
must be a writable four-byte object address, distinct from the EAX handle slot.
Linux has a different pthread model and is deliberately not registered here.
Old artifacts and generated signatures never participate in discovery.
"""

import inspect
import json

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from ida_preprocessor_scripts import x86_call_arguments
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals

LITERALS = (
    "Couldn't initialize network thread, run without -net_thread\n",
    "Couldn't initialize network thread, run with -nonetthread\n",
)

WALK = r"""
import ida_auto, ida_bytes, ida_funcs, ida_idp, ida_nalt, ida_segment, ida_ua, idaapi, idautils, idc, json

MAX_BODY = 8192
MAX_BACKTRACK = 4096
APIS = {'InitializeCriticalSection', 'CreateThread', 'DeleteCriticalSection'}
imports = {}
def collect_import(ea, name, ordinal):
    if name:
        name = name.lstrip('_').removeprefix('imp_').lstrip('_').split('@')[0]
        if name in APIS: imports[int(ea)] = name
    return True
globals().update(locals())
for index in range(ida_nalt.get_import_module_qty()):
    ida_nalt.enum_import_names(index, collect_import)

def api_name(target):
    for _ in range(4):
        if target in imports: return imports[target]
        if idc.print_insn_mnem(target).lower() != 'jmp': return None
        target = int(idc.get_operand_value(target, 0))
    return None

def writable(ea, width=4):
    seg = ida_segment.getseg(ea)
    return bool(seg and seg.perm & ida_segment.SEGPERM_WRITE
                and not seg.perm & ida_segment.SEGPERM_EXEC
                and ea % width == 0 and ea + width <= seg.end_ea)

def raw_body(start):
    pending, body = [start], {}
    while pending:
        ea = pending.pop()
        if ea in body: continue
        if not start <= ea < start + MAX_BODY: return None
        if ida_bytes.is_align(ida_bytes.get_flags(ea)): return None
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)
        if not size: return None
        mnem = insn.get_canon_mnem().lower()
        if mnem.startswith('loop'): return None
        if mnem in ('ret', 'retn', 'retf'): successors = []
        elif mnem.startswith('j'):
            if insn.ops[0].type != idaapi.o_near: return None
            successors = [int(insn.ops[0].addr)]
            if mnem != 'jmp': successors.append(ea + size)
        else: successors = [ea + size]
        body[ea] = {'ea':ea, 'insn':insn, 'size':size, 'mnem':mnem, 'successors':successors}
        pending.extend(successors)
    return [body[ea] for ea in sorted(body)]

def candidate_entry(site):
    chunk = ida_funcs.get_fchunk(site)
    if chunk is not None: return int(chunk.start_ea)
    cursor = site
    while site - cursor < MAX_BACKTRACK:
        previous = idc.prev_head(cursor)
        if previous == idaapi.BADADDR: return None
        if ida_bytes.is_align(ida_bytes.get_flags(previous)): return cursor
        cursor = previous
    return None

def tagged(op, ea, size, value):
    offset = int(op.offb)
    if offset <= 0 or offset + WORD > size: return ('unknown', None)
    if ida_bytes.get_dword(ea + offset) != value: return ('unknown', None)
    return ('imm', ('address', value, ea, offset, size))

def operand(op, ea, size, sp):
    if op.type == idaapi.o_reg:
        return ('reg', ida_idp.get_reg_name(op.reg, WORD).lower())
    if op.type == idaapi.o_imm:
        value = int(op.value)
        if ida_segment.getseg(value): return tagged(op, ea, size, value)
        return ('imm', value)
    if op.type in (idaapi.o_near, idaapi.o_far): return ('imm', int(op.addr))
    if op.type in (idaapi.o_displ, idaapi.o_phrase):
        text = idc.print_operand(ea, op.n).lower()
        if '[esp' in text and not any(r in text for r in ('eax','ebx','ecx','edx','esi','edi','ebp')):
            disp = int(op.addr) if op.type == idaapi.o_displ else 0
            if disp & 0x80000000: disp -= 0x100000000
            return ('stack', sp + disp)
    # Loading [ThreadId] would pass the runtime ID, never its address.
    return ('unknown', None)

def call_args(entries, index, arity):
    # Recover only within a straight-line definition region. Any incoming jump
    # to its interior makes the lexical definitions insufficient evidence.
    first = index
    while first > 0:
        prior = entries[first - 1]
        if prior['ea'] + prior['size'] != entries[first]['ea']: break
        if prior['mnem'] == 'call' or prior['mnem'].startswith('j') or prior['mnem'] in ('ret','retn'): break
        first -= 1
    region = entries[first:index+1]
    eas = {entry['ea'] for entry in region}
    for entry in region[1:]:
        if any(int(ref) not in eas for ref in idautils.CodeRefsTo(entry['ea'], False)): return None
    code, sp = [], 0
    for entry in region:
        insn, ea, size, mnem = entry['insn'], entry['ea'], entry['size'], entry['mnem']
        ops = [operand(op, ea, size, sp) for op in insn.ops if op.type != idaapi.o_void]
        if mnem == 'lea' and insn.ops[1].type == idaapi.o_mem:
            ops[1] = tagged(insn.ops[1], ea, size, int(insn.ops[1].addr))
            mnem = 'mov'
        code.append({'ea':ea, 'mnem':mnem, 'ops':ops, 'sp':sp})
        if mnem == 'push': sp -= WORD
        elif mnem == 'pop': sp += WORD
        elif ops and ops[0] == ('reg','esp'):
            if mnem == 'sub' and ops[1][0] == 'imm': sp -= ops[1][1]
            elif mnem == 'add' and ops[1][0] == 'imm': sp += ops[1][1]
            else: return None
    return recover_call_arguments(code, len(code)-1, arity)

def value(arg):
    return arg[1] if isinstance(arg, tuple) and arg[0] == 'address' else arg

def inspect_path(start, site, literal):
    entries = raw_body(start)
    if not entries or site not in {e['ea'] for e in entries}: return None
    calls = []
    for index, entry in enumerate(entries):
        if entry['mnem'] != 'call': continue
        op = entry['insn'].ops[0]
        target = int(op.addr) if op.type in (idaapi.o_mem,idaapi.o_near) else None
        if target is None: return None
        name = api_name(target)
        args = call_args(entries, index, 6 if name == 'CreateThread' else 1)
        calls.append({'index':index, 'ea':entry['ea'], 'target':target, 'name':name, 'args':args})
    creates = [c for c in calls if c['name'] == 'CreateThread']
    if len(creates) != 1: return None
    create = creates[0]
    args = create['args']
    if args is None or [value(args[i]) for i in (0,1,3,4)] != [0,0,0,0]: return None
    callback, tid = args[2], args[5]
    if not all(isinstance(a,tuple) and a[0] == 'address' for a in (callback,tid)): return None
    thread, thread_id = value(callback), value(tid)
    seg = ida_segment.getseg(thread)
    if not seg or not seg.perm & ida_segment.SEGPERM_EXEC or not writable(thread_id): return None
    init = [c for c in calls if c['name'] == 'InitializeCriticalSection' and c['ea'] < create['ea']]
    delete = [c for c in calls if c['name'] == 'DeleteCriticalSection' and c['ea'] > create['ea']]
    fatal = [c for c in calls if c['target'] == SYS_ERROR and c['args'] and value(c['args'][0]) == literal]
    if len(init) != 1 or len(delete) != 1 or len(fatal) != 1: return None
    if not init[0]['args'] or not delete[0]['args']: return None
    cs = value(init[0]['args'][0])
    if cs != value(delete[0]['args'][0]) or not writable(cs) or not create['ea'] < delete[0]['ea'] < site < fatal[0]['ea']:
        return None
    stores, other_writes = [], False
    for entry in entries:
        insn = entry['insn']
        if entry['mnem'] == 'mov' and insn.ops[0].type == idaapi.o_mem and writable(int(insn.ops[0].addr)):
            if ida_ua.get_dtype_size(insn.ops[0].dtype) != WORD:
                other_writes = True
                continue
            source = insn.ops[1]
            source_value = int(source.value) if source.type == idaapi.o_imm else None
            source_reg = ida_idp.get_reg_name(source.reg, WORD) if source.type == idaapi.o_reg else None
            stores.append((entry['ea'],int(insn.ops[0].addr),source_value,source_reg))
    rollback = {gv for ea,gv,v,r in stores if delete[0]['ea'] < ea < fatal[0]['ea'] and v == 0}
    initialized = {gv for ea,gv,v,r in stores if ea < init[0]['ea'] and v == 1} & rollback
    handles = {gv for ea,gv,v,r in stores if create['ea'] < ea < delete[0]['ea'] and r == 'eax'}
    if len(rollback) != 2 or len(initialized) != 1 or len(handles) != 1 or thread_id in rollback | handles: return None
    handle = next(iter(handles))
    handle_stores = [(ea,v,r) for ea,gv,v,r in stores if gv == handle]
    if len(handle_stores) != 1: return None
    # Verify the failed EAX result falls through to rollback, while a successful
    # result branches beyond it; do not trust proximity to the error string.
    guards = []
    for index, entry in enumerate(entries[:-1]):
        if not create['ea'] < entry['ea'] < delete[0]['ea']: continue
        op = entry['insn'].ops
        eax_test = entry['mnem'] == 'test' and all(o.type == idaapi.o_reg and ida_idp.get_reg_name(o.reg,WORD) == 'eax' for o in (op[0],op[1]))
        handle_test = (entry['mnem'] == 'cmp' and op[0].type == idaapi.o_mem
                       and int(op[0].addr) == handle and op[1].type == idaapi.o_imm and int(op[1].value) == 0
                       and handle_stores[0][0] < entry['ea'])
        if eax_test or handle_test:
            following = index + 1
            # MOV preserves TEST's flags. MSVC can store the returned handle
            # between TEST EAX,EAX and JNZ; that is still the same result test.
            while following < len(entries) and entries[following]['mnem'] == 'mov':
                destination = entries[following]['insn'].ops[0]
                if destination.type == idaapi.o_reg and ida_idp.get_reg_name(destination.reg,WORD) == 'eax':
                    break
                following += 1
            if following == len(entries): continue
            branch = entries[following]
            if branch['mnem'] in ('jnz','jne') and int(branch['insn'].ops[0].addr) > fatal[0]['ea']:
                guards.append(branch['ea'])
    if len(guards) != 1: return None
    graph = _control_flow(entries)
    indexes = {entry['ea']:index for index,entry in enumerate(entries)}
    fatal_index = indexes[fatal[0]['ea']]
    # Every failure execution must really perform setup and rollback. Lexical
    # ordering alone would also accept a jump that skipped DeleteCriticalSection.
    required = [init[0]['ea'],create['ea'],delete[0]['ea'],site]
    required.extend(ea for ea,gv,v,r in stores if gv in initialized and v == 1 and ea < init[0]['ea'])
    required.append(handle_stores[0][0])
    required.extend(ea for ea,gv,v,r in stores if delete[0]['ea'] < ea < fatal[0]['ea'] and gv in rollback and v == 0)
    if any(_may_reach(graph,0,fatal_index,blocked=indexes[ea]) for ea in required): return None
    pre_refs = {int(ref) for entry in entries if entry['ea'] < init[0]['ea'] for ref in idautils.DataRefsFrom(entry['ea'])}
    if not rollback <= pre_refs: return None
    allowed_calls = True
    for call in calls:
        if call['name'] in APIS or call in fatal: continue
        arg = value(call['args'][0]) if call['args'] else None
        text = ida_bytes.get_strlit_contents(arg,-1,0) if isinstance(arg,int) else None
        if not text or not text.startswith(b'Threaded networking '): allowed_calls = False
    standalone = allowed_calls and not other_writes and {gv for ea,gv,v,r in stores} == rollback | handles
    end = max(e['ea']+e['size'] for e in entries)
    return {'start':start, 'end':end, 'site':site, 'create':create['ea'], 'thread':thread,
            'tid':thread_id, 'tid_insn':tid[2], 'tid_disp':tid[3], 'tid_len':tid[4],
            'cs':cs, 'handle':next(iter(handles)), 'standalone':standalone}

def define_entry(start, end):
    owner = ida_funcs.get_func(start)
    chunk = ida_funcs.get_fchunk(start)
    if owner and int(owner.start_ea) != start:
        if not chunk or int(chunk.start_ea) != start or int(chunk.end_ea) > end or int(chunk.refqty) != 1:
            return False
        incoming = list(idautils.CodeRefsTo(start,False))
        if (len(incoming) != 1 or idc.print_insn_mnem(incoming[0]).lower() != 'jmp'
                or ida_funcs.get_func(incoming[0]).start_ea != owner.start_ea): return False
        chunk_end = int(chunk.end_ea)
        suffixes = []
        # Old IDBs stop this tail at the inferred noreturn Sys_Error call and
        # define its common guard-return RET as a separate nullsub. The current
        # CFG proves that RET belongs to the guarded start body. Only absorb
        # POP/RET suffix bytes with no incoming edge from outside this body.
        cursor = chunk_end
        while cursor < end:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn,cursor) or cursor + insn.size > end: return False
            if insn.get_canon_mnem().lower() not in ('pop','ret','retn'): return False
            if any(not start <= int(ref) < end for ref in idautils.CodeRefsTo(cursor,False)): return False
            suffix = ida_funcs.get_func(cursor)
            if suffix is not None:
                if not chunk_end <= int(suffix.start_ea) < int(suffix.end_ea) <= end: return False
                pair = (int(suffix.start_ea),int(suffix.end_ea))
                if pair not in suffixes: suffixes.append(pair)
            cursor += insn.size
        if not ida_funcs.remove_func_tail(owner,start): return False
        for suffix_start,suffix_end in suffixes:
            if not ida_funcs.del_func(suffix_start): raise ValueError('cannot detach proven return suffix')
        if not ida_funcs.add_func(start,end):
            for suffix_start,suffix_end in suffixes:
                ida_funcs.add_func(suffix_start,suffix_end)
            ida_funcs.append_func_tail(owner,start,chunk_end)
            return False
        owner = None
    if owner is None and ida_funcs.get_func(start) is None and not ida_funcs.add_func(start,end): return False
    function = ida_funcs.get_func(start)
    return bool(function and int(function.start_ea) == start and int(function.end_ea) == end)

def locate():
    if idaapi.inf_is_64bit(): raise ValueError('expected Windows x86')
    strings = []
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if seg.perm & ida_segment.SEGPERM_EXEC: continue
        for literal in LITERALS:
            needle = literal.encode() + b'\0'
            cursor = seg_start
            while cursor < seg.end_ea:
                ea = ida_bytes.find_bytes(needle,cursor,range_end=seg.end_ea,
                                         flags=ida_bytes.BIN_SEARCH_FORWARD|ida_bytes.BIN_SEARCH_NOSHOW)
                if ea == idaapi.BADADDR: break
                strings.append(int(ea)); cursor = ea + len(needle)
    if len(strings) != 1: raise ValueError('expected one exact creation-failure string: %r' % strings)
    literal = strings[0]
    paths = []
    for ref in idautils.DataRefsTo(literal):
        if not ida_bytes.is_code(ida_bytes.get_flags(ref)): continue
        start = candidate_entry(int(ref))
        if start is not None:
            path = inspect_path(start,int(ref),literal)
            if path is not None: paths.append(path)
    if not paths or len({(p['thread'],p['tid'],p['cs'],p['handle']) for p in paths}) != 1:
        raise ValueError('creation paths missing or disagree: %r' % paths)
    standalone = [p for p in paths if p['standalone']]
    if len(standalone) > 1: raise ValueError('ambiguous standalone NET_StartThread')
    path = standalone[0] if standalone else paths[0]
    if WANT_START != bool(standalone): raise ValueError('standalone/inline coverage differs from config')
    if standalone and not define_entry(path['start'],path['end']): raise ValueError('start entry recovery failed')
    thread = path['thread']
    function = ida_funcs.get_func(thread)
    if function is None:
        body = raw_body(thread)
        if not body or not define_entry(thread,max(e['ea']+e['size'] for e in body)):
            raise ValueError('thread callback entry recovery failed')
    elif int(function.start_ea) != thread: raise ValueError('callback is not an exact function entry')
    return {'pointer_size':4, 'literal':hex(literal), 'paths':paths, 'selected':path}

globals().update(locals())
try:
    result = json.dumps(locate())
except Exception as exc:
    result = json.dumps({'error':str(exc)})
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform != "windows":
        return False
    outputs = {
        name: _output_for_symbol(expected_outputs, name)
        for name in ("NET_StartThread", "NET_ThreadFunc", "dwNetThreadId")
    }
    if outputs["NET_ThreadFunc"] is None or outputs["dwNetThreadId"] is None:
        return False
    fatal = await inspect_owner_artifact(
        session, new_binary_dir, platform, image_base, "Sys_Error", allow_raw_span=True
    )
    if not fatal:
        return False
    # Reuse the exact validated predecessor signature, including old engines'
    # explicitly permitted extended signature, instead of generating a shorter
    # ambiguous prefix of the fatal-error wrapper again.
    fatal_ea = fatal["owner_ea"]
    code = (
        inspect.getsource(x86_call_arguments)
        + f"\nLITERALS={LITERALS!r}\nSYS_ERROR={fatal_ea}\nWANT_START={outputs['NET_StartThread'] is not None!r}\n"
        + WALK
    )
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: {located}")
        return False
    path = located["selected"]
    if debug:
        print(f"  {skill_name}: {json.dumps(located)}")
    functions = {}
    for name, ea in (("NET_StartThread", path["start"]), ("NET_ThreadFunc", path["thread"])):
        if outputs[name] is None:
            continue
        function = await _inspect_function_via_mcp(
            session, ea, image_base, name, allow_relative_call_discriminator=True
        )
        if function is None:
            return False
        function.pop("_pointer_size", None)
        functions[name] = function
    owner = functions.get("NET_StartThread")
    if owner is None:
        owner = await _inspect_function_via_mcp(session, path["start"], image_base, "NET_Init")
    if owner is None:
        return False
    # Inline copies can make the lpThreadId PUSH byte-identical. Use the unique
    # owning-body signature and retain the verified operand offset, as in the
    # other semantic GV finders. The resolver still reads the operand's DWORD.
    context = {"owner_ea": path["start"], "owner_end": path["end"], "function": owner, "allow_across": False}
    item = {
        "gv_ea": path["tid"],
        "insn_ea": path["tid_insn"],
        "insn_len": path["tid_len"],
        "insn_disp": path["tid_disp"],
    }
    if not await write_located_globals(
        session, expected_outputs, platform, image_base, context, {"dwNetThreadId": item}
    ):
        return False
    for name, function in functions.items():
        write_func_yaml(outputs[name], function)
    return True
