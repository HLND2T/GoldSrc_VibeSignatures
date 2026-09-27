#!/usr/bin/env python3
"""Recover ``host_parms`` (its ``basedir`` member) from Host_InitializeGameDLL.

``engine/host.c`` declares ``quakeparms_t host_parms`` and ``basedir`` is its
first member, so ``host_parms.basedir`` and ``&host_parms`` resolve to the same
32-bit address. Host_InitializeGameDLL passes that member to
``LoadEntityDLLs(host_parms.basedir)`` after clearing ``svs.dll_initialized``:

    svs.dll_initialized = true;
    LoadEntityDLLs(host_parms.basedir);

MetaHookSv's ``Engine_FillAddress_Sys_InitializeGameDLL`` instead walks a
``push <string>; call ...; add esp, 4; retn`` window after the diagnostic and
grabs the first data operand it meets, which is a one-family byte pattern, not
a unique anchor here.

The reproducible invariant is the LoadEntityDLLs call argument itself.
``LoadEntityDLLs`` owns the exact literal ``"GetNewDLLFunctions"`` (a string
that must be exported by every loaded game library), so it has exactly one
owning function on every configured engine build. Inside the revalidated
Host_InitializeGameDLL body — including GCC's separated tail body on hl-8684
Linux — the direct call to that owner receives exactly one argument whose
decoded value is a writable 32-bit global; that global is ``host_parms``. The
finder fails closed unless the call argument resolves to exactly one candidate
across all supported encodings (MSVC absolute load/push, GCC absolute load,
SvEngine GOTOFF ``lea``, and SvEngine 8948 Linux's GOT-slot pointer load). No
LLM step and no byte signature participate in discovery.
"""

import inspect

from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk
from ida_preprocessor_scripts import x86_call_arguments

OWNER_NAME = "Host_InitializeGameDLL"
GV_NAME = "host_parms"
LOADENT_ANCHOR = "GetNewDLLFunctions"
LOOKBACK = 12

# The decoder is injected with the shared engine-private walk and the inlined
# call-argument recovery module; only the candidate address crosses MCP.
WALK = (
    inspect.getsource(x86_call_arguments)
    + "\n"
    + r"""
import ida_frame
import ida_name
import re

LOADENT_ANCHOR = values['loadent_anchor']
OWNER_EA = int(values['owner'], 0)
LOOKBACK = int(values['lookback'])


def func_start(ea):
    func = ida_funcs.get_func(int(ea))
    return None if func is None else int(func.start_ea)


def loadent_owner():
    # Scan readable segments for the exact NUL-delimited C literal instead of
    # the shared string list: strings.setup() rebuilds IDB-wide state that
    # later skills enumerate. A trailing NUL plus a preceding NUL/segment
    # start give FULLMATCH semantics.
    needle = LOADENT_ANCHOR.encode('ascii') + b'\x00'
    owners = set()
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(int(seg_start))
        if seg is None or not (int(getattr(seg, 'perm', 0)) & 4):
            continue
        span = int(seg.end_ea) - int(seg_start)
        if span <= 0:
            continue
        try:
            data = ida_bytes.get_bytes(int(seg_start), span)
        except Exception:
            continue
        if not data:
            continue
        offset = data.find(needle)
        while offset != -1:
            if offset == 0 or data[offset - 1] == 0:
                for xref in idautils.DataRefsTo(int(seg_start) + offset):
                    start = func_start(xref)
                    if start is not None:
                        owners.add(start)
            offset = data.find(needle, offset + 1)
    return sorted(owners)


def tail_bodies(start):
    # GCC may place the LoadEntityDLLs call in a separated tail function (the
    # unconditional jmp target from the diagnostic-bearing body).
    out = []
    for ea in idautils.FuncItems(int(start)):
        if (idc.print_insn_mnem(ea) or '').lower() != 'jmp':
            continue
        if idc.get_operand_type(ea, 0) != idaapi.o_near:
            continue
        target = int(idc.get_operand_value(ea, 0))
        func = ida_funcs.get_func(target)
        if func is not None and int(func.start_ea) == target and target != int(start):
            out.append(target)
    return sorted(set(out))


def address_def(entries, index, reg, graph, got_register):
    for previous in range(index - 1, max(-1, index - LOOKBACK - 1), -1):
        entry = entries[previous]
        mnemonic = entry['mnem']
        if mnemonic == 'call' or mnemonic.startswith('j') or mnemonic in ('ret', 'retn', 'retf', 'loop'):
            return None
        insn = entry['insn']
        destination = insn.ops[0]
        if int(destination.type) != int(idaapi.o_reg) or reg4(destination) != reg:
            continue
        if not changed_operand(insn, 0):
            continue
        if not _may_reach(graph, 0, index) or _may_reach(graph, 0, index, blocked=previous):
            return None
        if len(entry['targets']) != 1 or entry['written'] or not entry['disp']:
            return None
        source = insn.ops[1]
        gv = next(iter(entry['targets']))
        if mnemonic == 'lea':
            if int(source.type) == int(idaapi.o_mem) and int(source.addr) == gv:
                return entry, gv, 'lea-abs'
            if int(source.type) == int(idaapi.o_displ) and got_register and reg4(source) == got_register:
                return entry, gv, 'lea-gotoff'
            return None
        if mnemonic == 'mov' and int(source.type) == int(idaapi.o_displ) and got_register and reg4(source) == got_register:
            if any(is_got(int(ref)) for ref in idautils.DataRefsFrom(entry['ea'])):
                return entry, gv, 'got-load'
        return None
    return None


def encode_source(entries, index, op, op_index, stack_pointer, graph, got_register):
    entry = entries[index]
    kind = int(op.type)
    if kind == int(idaapi.o_imm):
        return ('imm', int(op.value) & 0xFFFFFFFF)
    if kind == int(idaapi.o_reg):
        return ('reg', reg4(op))
    if kind == int(idaapi.o_mem):
        gv = int(op.addr) & 0xFFFFFFFF
        if (ida_ua.get_dtype_size(op.dtype) == 4 and entry['targets'] == {gv}
                and not entry['written'] and entry['disp'] and is_writable_data(gv)):
            return ('imm', ('load', access(entry, gv), 'abs'))
        return ('unknown', None)
    if kind not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
        return ('unknown', None)
    # Structural ESP-slot test: SIB base esp, no index. IDA's text operand may
    # embed stack-variable names such as szBaseDir that contain register names.
    if int(op.specflag1):
        sib = int(op.specflag2) & 0xFF
        esp_slot = (sib & 7) == 4 and ((sib >> 3) & 7) == 4
    else:
        esp_slot = False
    if esp_slot:
        displacement = signed32(op.addr) if kind == int(idaapi.o_displ) else 0
        if ida_ua.get_dtype_size(op.dtype) == 4 and displacement % 4 == 0:
            return ('stack', stack_pointer + displacement)
        return ('unknown', None)
    text = (idc.print_operand(entry['ea'], op_index) or '').lower()
    base = reg4(op)
    if (not base or ida_ua.get_dtype_size(op.dtype) != 4
            or (kind == int(idaapi.o_displ) and signed32(op.addr) != 0)
            or re.fullmatch(r'(?:dword ptr\s+)?(?:(?:ds|ss):)?\[' + re.escape(base) + r'\]', text.strip()) is None):
        return ('unknown', None)
    found = address_def(entries, index, base, graph, got_register)
    if found is None:
        return ('unknown', None)
    def_entry, gv, how = found
    return ('imm', ('load', access(def_entry, gv), how))


loadent = loadent_owner()
if len(loadent) != 1:
    result = {'error': 'LoadEntityDLLs literal owner is not unique',
              'owners': [hex(o) for o in loadent]}
else:
    loadent_ea = loadent[0]
    bodies = [OWNER_EA] + tail_bodies(OWNER_EA)
    found = []
    for body in bodies:
        func = ida_funcs.get_func(body)
        entries = scan(body)
        if entries is None:
            continue
        got_base, got_register = got_anchor(body)
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
        graph = _control_flow([
            {'mnem': entry['mnem'], 'ea': entry['ea'], 'successors': flow[entry['ea']]}
            for entry in entries
        ])
        code = []
        for index, entry in enumerate(entries):
            insn = entry['insn']
            stack_pointer = int(ida_frame.get_spd(func, entry['ea']))
            operands = []
            for op_index, op in enumerate(insn.ops):
                if int(op.type) == int(idaapi.o_void):
                    break
                if int(op.type) == int(idaapi.o_reg) and (op_index == 0 or ida_ua.get_dtype_size(op.dtype) == 4):
                    operands.append(('reg', reg4(op)))
                else:
                    operands.append(encode_source(entries, index, op, op_index, stack_pointer, graph, got_register))
            mnemonic = entry['mnem']
            if operands and operands[0][0] == 'reg' and ida_ua.get_dtype_size(insn.ops[0].dtype) != 4:
                mnemonic = 'unknown_write'
            code.append({
                'mnem': mnemonic,
                'ops': operands,
                'sp': stack_pointer,
                'ea': entry['ea'],
                'successors': flow[entry['ea']],
            })
        for index, entry in enumerate(entries):
            if entry['mnem'] != 'call' or local_call_target(entry['ea']) != loadent_ea:
                continue
            arguments = recover_call_arguments(code, index, 1)
            found.append((body, entry['ea'], arguments[0]))
    if len(found) != 1 or not isinstance(found[0][2], tuple) or found[0][2][0] != 'load':
        result = {
            'error': 'host_parms.basedir LoadEntityDLLs argument is not unique',
            'loadent_ea': hex(loadent_ea),
            'bodies': [hex(body) + ':' + ida_name.get_name(body) for body in bodies],
            'found': [(hex(b), hex(c), repr(a)[:120]) for b, c, a in found],
        }
    else:
        body, call_ea, arg = found[0]
        located = arg[1]
        result = {
            'pointer_size': 4,
            'owner_ea': hex(body),
            'call_ea': hex(call_ea),
            'gv': located,
            'encoding': arg[2],
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
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: missing or invalid {OWNER_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK,
        {"owner": hex(owner["owner_ea"]), "loadent_anchor": LOADENT_ANCHOR, "lookback": LOOKBACK},
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    # GCC may place the LoadEntityDLLs call (and its ``host_parms`` reference)
    # in a separated tail function. Anchor the artifact to the body that
    # actually contains the selected instruction, then revalidate that body.
    ref_owner_ea = int(located["owner_ea"], 0)
    if ref_owner_ea == owner["owner_ea"]:
        anchor_owner = owner
    else:
        anchor_owner = await owner_context(session, ref_owner_ea, image_base, OWNER_NAME)
        if anchor_owner is None:
            if debug:
                print(f"{skill_name}: failed to inspect the reference body at {ref_owner_ea:#x}")
            return False
    return await write_located_globals(
        session, expected_outputs, platform, image_base, anchor_owner, {GV_NAME: located["gv"]}
    )
