#!/usr/bin/env python3
"""Locate GL_Shutdown through the Sys_Shutdown() trace literal.

GL_Shutdown (engine/gl_vidnt.c, Windows; a tiny stub on the Linux builds that
keep it) owns no diagnostic string. The deterministic locator is the
TRACESHUTDOWN literal "Sys_Shutdown()" from sys_dll2.cpp: every build keeps it
in at most two owners (Sys_InitGame references it as the TraceInit shutdown
pair, the real shutdown path references it through TraceShutdown). Inside the
owner functions and their direct callees (CoF routes the call through
Sys_Shutdown one level deeper), GL_Shutdown is the unique direct call preceded
by at least three loads from three distinct absolute globals and three
register argument writes (push reg / mov [esp+X], reg) whose target is a small
function. That call-shape discriminates GL_Shutdown(*pmainwindow, maindc,
baseRC) from every TraceShutdown/TraceInit wrapper call, which only pushes
immediate offsets. Discovery uses the string anchor plus current-binary
instruction semantics; no byte signature or old YAML is used for locating.
"""

from ida_analyze_util import (
    _find_unique_bytes,
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNCTION_NAME = "GL_Shutdown"
ANCHOR_STRING = "Sys_Shutdown()"
MAX_TARGET_SIZE = 0x200
CALL_WINDOW_INSTRUCTIONS = 16
MAX_OWNER_CALLEES = 64

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

ANCHOR_STRING = ANCHOR_STRING_PLACEHOLDER
MAX_TARGET_SIZE = MAX_TARGET_SIZE_PLACEHOLDER
CALL_WINDOW_INSTRUCTIONS = CALL_WINDOW_INSTRUCTIONS_PLACEHOLDER
MAX_OWNER_CALLEES = MAX_OWNER_CALLEES_PLACEHOLDER


def insn_mnem(ea):
    return (idc.print_insn_mnem(int(ea)) or '').lower()


def func_start(ea):
    func = ida_funcs.get_func(int(ea))
    return None if func is None else int(func.start_ea)


def anchor_string_owners():
    owners = set()
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)
    for item in strings:
        if str(item) != ANCHOR_STRING:
            continue
        for xref in idautils.DataRefsTo(int(item.ea)):
            start = func_start(xref)
            if start is not None:
                owners.add(start)
    return sorted(owners)


def direct_callees(start):
    callees = []
    for ea in idautils.FuncItems(int(start)):
        if insn_mnem(ea) not in ('call', 'jmp'):
            continue
        raw = ida_bytes.get_bytes(int(ea), 5) or b''
        if len(raw) < 5 or raw[0] not in (0xE8, 0xE9):
            continue
        import struct
        rel = struct.unpack('<i', raw[1:5])[0]
        target = int(ea) + 5 + rel
        callee = ida_funcs.get_func(target)
        if callee is not None and int(callee.start_ea) == target:
            callees.append(target)
        if len(callees) >= int(MAX_OWNER_CALLEES):
            break
    return callees


def call_argument_globals(items, call_index):
    # Argument shape of the call at items[call_index]. The window stops at the
    # preceding call/jmp so a trailing tail-chunk call cannot reuse an earlier
    # call's argument setup. Requires three distinct absolute-global argument
    # sources (mov reg,[abs] or push [abs]), three argument writes (push reg,
    # push [reg], push [abs], or mov [esp+X],reg), and the pmainwindow-style
    # double dereference (a register loaded from an absolute global is
    # re-read through [reg]).
    abs_addrs = set()
    param_writes = 0
    double_deref = False
    regs_from_abs = set()
    window_start = call_index
    while window_start > 0 and call_index - window_start < int(CALL_WINDOW_INSTRUCTIONS):
        prev = items[window_start - 1]
        if insn_mnem(prev) in ('call', 'jmp'):
            break
        window_start -= 1
    for ea in items[window_start:call_index]:
        insn = idautils.DecodeInstruction(int(ea))
        if insn is None:
            continue
        mnem = insn_mnem(ea)
        if mnem == 'push':
            op = insn.ops[0]
            if int(op.type) == int(idaapi.o_reg):
                param_writes += 1
            elif int(op.type) in (int(idaapi.o_phrase), int(idaapi.o_displ)):
                param_writes += 1
                base = int(getattr(op, 'phrase', 0) or 0) or int(getattr(op, 'reg', 0))
                if base in regs_from_abs:
                    double_deref = True
            elif int(op.type) == int(idaapi.o_mem):
                param_writes += 1
                abs_addrs.add(int(op.addr))
            continue
        if mnem in ('mov', 'movl'):
            dst, src = insn.ops[0], insn.ops[1]
            if int(dst.type) == int(idaapi.o_reg) and int(src.type) == int(idaapi.o_mem):
                abs_addrs.add(int(src.addr))
                regs_from_abs.add(int(dst.reg))
            elif int(dst.type) == int(idaapi.o_reg) and int(src.type) in (
                int(idaapi.o_phrase),
                int(idaapi.o_displ),
            ):
                base = int(getattr(src, 'phrase', 0) or 0) or int(getattr(src, 'reg', 0))
                if base in regs_from_abs:
                    double_deref = True
            elif (
                int(dst.type) in (int(idaapi.o_phrase), int(idaapi.o_displ))
                and (int(getattr(dst, 'phrase', 0) or 0) or int(getattr(dst, 'reg', 0))) == 4
                and int(src.type) == int(idaapi.o_reg)
            ):
                param_writes += 1
    return abs_addrs, param_writes, double_deref



def sig_count(tokens, expected):
    if not tokens or all(token == '??' for token in tokens):
        return 0
    data = bytes(0 if token == '??' else int(token, 16) for token in tokens)
    mask = bytes(0x00 if token == '??' else 0xFF for token in tokens)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
    found_hits = []
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(int(seg_start))
        if seg is None or not (int(getattr(seg, 'perm', 0)) & 4):
            continue
        ea = int(seg.start_ea)
        while len(found_hits) < 3:
            found = ida_bytes.find_bytes(data, ea, range_end=int(seg.end_ea), mask=mask, flags=flags)
            if found is None or found == idaapi.BADADDR:
                break
            found_hits.append(int(found))
            ea = int(found) + 1
        if len(found_hits) >= 3:
            break
    unique_hits = sorted(set(found_hits))
    if expected is not None and unique_hits == [int(expected)]:
        return 1
    return len(unique_hits)


def wildcard_insn_tokens(insn, raw, pin_branches):
    import ida_ua
    wild = set()
    relocatable_types = (
        int(idaapi.o_imm),
        int(idaapi.o_far),
        int(idaapi.o_mem),
        int(idaapi.o_displ),
    )
    if not pin_branches:
        relocatable_types = relocatable_types + (int(idaapi.o_near),)
    for op in insn.ops:
        ot = int(op.type)
        if ot == int(idaapi.o_void):
            continue
        if ot in relocatable_types:
            offb = int(getattr(op, 'offb', 0))
            if 0 < offb < insn.size:
                dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                if dsz <= 0:
                    dsz = insn.size - offb
                for index in range(offb, min(insn.size, offb + dsz)):
                    wild.add(index)
    if not pin_branches:
        b0 = raw[0]
        if b0 in (0xE8, 0xE9, 0xEB):
            for index in range(1, insn.size):
                wild.add(index)
        elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:
            for index in range(2, insn.size):
                wild.add(index)
        elif 0x70 <= b0 <= 0x7F:
            for index in range(1, insn.size):
                wild.add(index)
    return ['??' if index in wild else '%02X' % raw[index] for index in range(insn.size)]


def generate_unique_sig(target, limit):
    # Forward-only expansion from the function start, pinning immediates and
    # wildcarding relocatable operands, until the token stream is unique.
    # Needed where GL_Shutdown inlines another body (HL25 Linux inlines
    # FreeFBOObjects) so the standard prologue window cannot separate the two
    # functions. A second pass pins branch displacements so a tiny jmp thunk
    # (SvEngine) still yields a unique signature; per-version artifacts may pin
    # them because the relative displacement is fixed at link time.
    for pin_branches in (False, True):
        tokens = []
        boundaries = []
        cursor = int(target)
        guard = 0
        while cursor < int(limit) and guard < 256:
            insn = idautils.DecodeInstruction(cursor)
            if not insn or insn.size <= 0:
                break
            raw = ida_bytes.get_bytes(cursor, insn.size)
            if not raw:
                break
            tokens.extend(wildcard_insn_tokens(insn, raw, pin_branches))
            boundaries.append(len(tokens))
            cursor += insn.size
            guard += 1
            if len(boundaries) >= 1 and sig_count(tokens, target) == 1:
                return ' '.join(tokens)
        for boundary in boundaries:
            if boundary < 6:
                continue
            prefix = tokens[:boundary]
            if sig_count(prefix, target) == 1:
                return ' '.join(prefix)
    return None


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owners = anchor_string_owners()
    if not owners:
        raise RuntimeError('anchor string has no function owner')
    scan_set = list(owners)
    for owner in owners:
        for callee in direct_callees(owner):
            if callee not in scan_set:
                scan_set.append(callee)
    candidates = []
    for start in scan_set:
        func = ida_funcs.get_func(int(start))
        if func is None:
            continue
        items = [ea for ea in idautils.FuncItems(int(start))]
        for index, ea in enumerate(items):
            if insn_mnem(ea) != 'call':
                continue
            raw = ida_bytes.get_bytes(int(ea), 5) or b''
            if len(raw) < 5 or raw[0] != 0xE8:
                continue
            import struct
            rel = struct.unpack('<i', raw[1:5])[0]
            target = int(ea) + 5 + rel
            callee = ida_funcs.get_func(target)
            if callee is None or int(callee.start_ea) != target:
                continue
            if int(callee.end_ea) - target > int(MAX_TARGET_SIZE):
                continue
            abs_addrs, param_writes, double_deref = call_argument_globals(items, index)
            if len(abs_addrs) >= 3 and param_writes >= 3 and double_deref:
                candidates.append({
                    'callsite': hex(int(ea)),
                    'owner': hex(int(start)),
                    'target': hex(int(target)),
                    'target_size': hex(int(callee.end_ea) - target),
                    'globals': sorted(hex(a) for a in abs_addrs),
                })
    unique_targets = sorted({c['target'] for c in candidates})
    if len(unique_targets) != 1:
        result = json.dumps({
            'error': 'GL_Shutdown call shape is not unique',
            'owners': [hex(o) for o in owners],
            'candidates': candidates,
        })
    else:
        target = int(unique_targets[0], 0)
        func = ida_funcs.get_func(target)
        unique_sig = generate_unique_sig(target, int(func.end_ea) if func else target + 0x200)
        if not unique_sig:
            result = json.dumps({
                'error': 'failed to generate a unique GL_Shutdown signature',
                'owners': [hex(o) for o in owners],
                'func_ea': unique_targets[0],
            })
        else:
            try:
                import ida_name
                ida_name.set_name(target, 'GL_Shutdown', ida_name.SN_FORCE)
            except Exception:
                pass
            result = json.dumps({
                'pointer_size': 4,
                'func_ea': unique_targets[0],
                'func_size': hex(int(func.end_ea) - target) if func else None,
                'func_sig': unique_sig,
                'owners': [hex(o) for o in owners],
                'callsites': [c['callsite'] for c in candidates],
            })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def _locate_gl_shutdown(session):
    code = (
        LOCATE_PY.replace("ANCHOR_STRING_PLACEHOLDER", repr(ANCHOR_STRING))
        .replace("MAX_TARGET_SIZE_PLACEHOLDER", str(MAX_TARGET_SIZE))
        .replace("CALL_WINDOW_INSTRUCTIONS_PLACEHOLDER", str(CALL_WINDOW_INSTRUCTIONS))
        .replace("MAX_OWNER_CALLEES_PLACEHOLDER", str(MAX_OWNER_CALLEES))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    return payload


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
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNCTION_NAME)
    if output is None:
        return False
    located = await _locate_gl_shutdown(session)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-GL_Shutdown: locator failed {located}")
        return False
    try:
        func_ea = int(located["func_ea"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    if func_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, func_ea, image_base, TARGET_FUNCTION_NAME)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session,
            func_ea,
            image_base,
            TARGET_FUNCTION_NAME,
            allow_across_function_boundary=True,
        )
        allow_across = True
    if not function or not function.get("func_sig"):
        fallback_sig = located.get("func_sig")
        if not isinstance(fallback_sig, str) or not fallback_sig.strip():
            if debug:
                print(f"  find-GL_Shutdown: function inspect failed ea={located.get('func_ea')}")
            return False
        if await _find_unique_bytes(session, fallback_sig) != func_ea:
            if debug:
                print(f"  find-GL_Shutdown: fallback signature is not unique ea={located.get('func_ea')}")
            return False
        function = {
            "func_va": hex(func_ea),
            "func_rva": hex(func_ea - int(image_base)),
            "func_size": located.get("func_size"),
            "func_sig": fallback_sig,
        }
    try:
        inspected_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_va != func_ea:
        return False
    if debug:
        print(f"  find-GL_Shutdown: ea={function['func_va']} size={function.get('func_size')} across={allow_across}")
    payload = {
        "func_name": TARGET_FUNCTION_NAME,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
