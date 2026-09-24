"""Shared x86 global/callsite walk for engine-private symbol locators.

The decoder is injected into the owned IDA worker so only candidate addresses
cross MCP. It resolves the writable-data globals an instruction touches on all
three GoldSrc build flavours:

* MSVC absolute operands (``mov al, byte ptr ds:gWaterColor``),
* GCC non-PIC absolute operands (``mov eax, ds:gWaterColor``),
* GCC PIC, either GOT-base relative (``lea eax, (gv - GOT)[ebx]``) or through a
  ``.got`` slot whose pointee is the real object.

Writes are classified from the instruction's canonical ``CF_CHG`` feature so x87
stores (``fstp ds:cl_viewangles``) count as writes while ``fld`` does not.
"""

import json

from ida_analyze_util import _inspect_function_via_mcp, parse_mcp_result
from ida_elf import ELF_RESOLVER_PY

DECODER = (
    ELF_RESOLVER_PY
    + r"""
import ida_bytes, ida_funcs, ida_idp, ida_nalt, ida_segment, ida_ua, idaapi, idautils, idc


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(ida_segment.SEGPERM_WRITE)) and not bool(perms & int(ida_segment.SEGPERM_EXEC))


def is_readable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(ida_segment.SEGPERM_READ)) and not bool(perms & int(ida_segment.SEGPERM_EXEC))


def is_code_address(ea):
    seg = ida_segment.getseg(int(ea))
    return seg is not None and bool(int(getattr(seg, 'perm', 0)) & int(ida_segment.SEGPERM_EXEC))


def is_got(ea):
    seg = ida_segment.getseg(int(ea))
    return seg is not None and ida_segment.get_segm_name(seg) in ('.got', '.got.plt')


def is_plt(ea):
    seg = ida_segment.getseg(int(ea))
    return seg is not None and ida_segment.get_segm_name(seg).startswith('.plt')


def reg4(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def reg1(op):
    if int(op.type) != int(idaapi.o_reg):
        return None
    try:
        return (ida_idp.get_reg_name(int(op.reg), 1) or '').lower() or None
    except Exception:
        return None


def signed32(value):
    value = int(value) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def disp32_offset(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and int(insn.size) - offb >= 4 and int(op.type) in (
                int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_imm), int(idaapi.o_phrase)):
            return offb
    return 0


def changed_operand(insn, index):
    return bool(insn.get_canon_feature() & int(getattr(ida_idp, 'CF_CHG%d' % (index + 1))))


# (base, register) of the PIC prologue "call thunk; add reg, imm32".
def got_anchor(start):
    items = list(idautils.FuncItems(int(start)))[:10]
    for index, current in enumerate(items):
        if (idc.print_insn_mnem(current) or '').lower() != 'call':
            continue
        following = items[index + 1] if index + 1 < len(items) else None
        if following is None or (idc.print_insn_mnem(following) or '').lower() != 'add':
            continue
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, following):
            continue
        if int(insn.ops[0].type) != int(idaapi.o_reg) or int(insn.ops[1].type) != int(idaapi.o_imm):
            continue
        callee = idc.get_operand_value(current, 0)
        thunk = ida_funcs.get_func(callee) if callee else None
        if thunk is None or int(thunk.end_ea) - int(thunk.start_ea) > 4:
            continue
        return (int(following) + int(insn.ops[1].value)) & 0xFFFFFFFF, reg4(insn.ops[0])
    return None, None


# {global address: {operand index}} for one instruction. Operand-derived
# addresses win; IDA's data xrefs are only consulted when the operands name
# nothing, because a PIC x87 member access records the struct base rather than
# the accessed member.
def operand_globals(ea, insn, bases):
    found = {}
    for index, op in enumerate(insn.ops):
        kind = int(op.type)
        if kind == int(idaapi.o_void):
            break
        # A GOT slot is never the requested object; its pointee is resolved below.
        if kind == int(idaapi.o_mem) and is_writable_data(int(op.addr)) and not is_got(int(op.addr)):
            found.setdefault(int(op.addr), set()).add(index)
        elif kind in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            base = reg4(op)
            if base in bases:
                value = (int(bases[base]) + signed32(op.addr)) & 0xFFFFFFFF
                if is_writable_data(value) and not is_got(value):
                    found.setdefault(value, set()).add(index)
    carrier = None
    for index, op in enumerate(insn.ops):
        if int(op.type) == int(idaapi.o_void):
            break
        if int(getattr(op, 'offb', 0) or 0):
            carrier = index
            break
    slots = {carrier} if carrier is not None else set()
    for ref in idautils.DataRefsFrom(int(ea)):
        ref = int(ref)
        if is_got(ref):
            pointee = int(ida_bytes.get_dword(ref))
            if is_writable_data(pointee):
                found.setdefault(pointee, set()).update(slots)
        elif is_writable_data(ref) and not found:
            found.setdefault(ref, set()).update(slots)
    return found


# Decode one function, or a signature-verified byte span when IDA has not
# established the artifact's function boundary.
def scan(start, end=None):
    if end is None:
        owner = ida_funcs.get_func(int(start))
        if owner is None or int(owner.start_ea) != int(start):
            return None
        items = idautils.FuncItems(int(start))
    else:
        start, end = int(start), int(end)
        first_segment = ida_segment.getseg(start)
        last_segment = ida_segment.getseg(end - 1) if end > start else None
        if (first_segment is None or last_segment is None
                or int(first_segment.start_ea) != int(last_segment.start_ea)
                or not is_code_address(start) or not is_code_address(end - 1)):
            return None
        items = []
        cursor = start
        while cursor < end:
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, cursor)
            if not size or cursor + int(size) > end:
                return None
            items.append(cursor)
            cursor += int(size)
    bases = {}
    provenance = {}
    entries = []
    got_base, got_register = got_anchor(start) if end is None else (None, None)
    if got_base is not None:
        bases[got_register] = got_base
    for ea in items:
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            if end is not None:
                return None
            continue
        mnemonic = (idc.print_insn_mnem(int(ea)) or '').lower()
        targets = operand_globals(int(ea), insn, bases)
        written = {gv for gv, indexes in targets.items() if any(changed_operand(insn, i) for i in indexes)}
        entries.append({
            'ea': int(ea),
            'insn': insn,
            'mnem': mnemonic,
            'targets': set(targets),
            'written': written,
            'len': int(insn.size),
            'disp': disp32_offset(insn),
            'disasm': idc.generate_disasm_line(int(ea), 0) or '',
            'provenance': dict(provenance),
        })
        destination = insn.ops[0]
        source = insn.ops[1]
        if int(destination.type) != int(idaapi.o_reg):
            continue
        name = reg4(destination)
        if got_base is not None and name == got_register:
            continue
        # Address-load tracking for later member accesses through the register.
        base = None
        origin = None
        if mnemonic == 'lea' and int(source.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            if reg4(source) in ('esp', 'ebp'):
                origin = ('stack', signed32(source.addr))
            elif len(targets) == 1 and int(source.type) == int(idaapi.o_displ):
                base = next(iter(targets))
        elif mnemonic == 'mov' and int(source.type) in (int(idaapi.o_mem), int(idaapi.o_displ)):
            if int(source.type) == int(idaapi.o_mem):
                origin = ('mem', int(source.addr))
            if any(is_got(int(ref)) for ref in idautils.DataRefsFrom(int(ea))) and len(targets) == 1:
                base = next(iter(targets))
        bases.pop(name, None)
        provenance.pop(name, None)
        if base is not None:
            bases[name] = base
        if origin is not None:
            provenance[name] = origin


    return entries


# {global address: [entry index]} for entries naming exactly one global.
def single_globals(entries):
    mapping = {}
    for index, entry in enumerate(entries):
        if len(entry['targets']) == 1:
            mapping.setdefault(next(iter(entry['targets'])), []).append(index)
    return mapping


# The first entry whose operand carries a four-byte displacement.
def first_addressable(entries, indexes):
    for index in indexes:
        if entries[index]['disp']:
            return entries[index]
    return None


def access(entry, gv):
    if entry is None:
        return None
    return {
        'gv_ea': hex(int(gv)),
        'insn_ea': hex(int(entry['ea'])),
        'insn_len': hex(int(entry['len'])),
        'insn_disp': hex(int(entry['disp'])),
        'insn_disasm': entry['disasm'],
    }


# Direct call target resolved past a PLT stub, else None.
def local_call_target(ea):
    if idc.get_operand_type(int(ea), 0) != int(idaapi.o_near):
        return None
    target = resolve_elf_plt(idc.get_operand_value(int(ea), 0))
    if is_plt(target):
        return None
    function = ida_funcs.get_func(target)
    return int(target) if function is not None and int(function.start_ea) == target else None


# {callee: [call site]} over the function's direct calls.
def direct_calls(start):
    owner = ida_funcs.get_func(int(start))
    result = {}
    for ea in idautils.FuncItems(int(start)):
        if (idc.print_insn_mnem(ea) or '').lower() != 'call':
            continue
        target = local_call_target(ea)
        if target is not None and (owner is None or target != int(owner.start_ea)):
            result.setdefault(target, []).append(int(ea))
    return result


# {(caller start, call site)} including calls routed through a PLT stub.
def callers(target):
    found = set()
    for ref in idautils.CodeRefsTo(int(target), 0):
        function = ida_funcs.get_func(int(ref))
        if function is not None and not is_plt(int(function.start_ea)):
            found.add((int(function.start_ea), int(ref)))
    for slot in idautils.DataRefsTo(int(target)):
        if not is_got(slot):
            continue
        for stub in idautils.DataRefsTo(slot):
            stub_function = ida_funcs.get_func(stub)
            if stub_function is None or not is_plt(int(stub_function.start_ea)):
                continue
            for ref in idautils.CodeRefsTo(int(stub_function.start_ea), 0):
                function = ida_funcs.get_func(int(ref))
                if function is not None and not is_plt(int(function.start_ea)):
                    found.add((int(function.start_ea), int(ref)))
    return found


# The single function owning the single exact C string, else None.
def exact_string_owner(literal):
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    matches = [int(item.ea) for item in strings if str(item) == literal]
    if len(matches) != 1:
        return None
    owners = set()
    for ref in idautils.XrefsTo(matches[0], 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.add(int(function.start_ea))
    return sorted(owners)[0] if len(owners) == 1 else None
"""
)


async def run_walk(session, body, values=None):
    """Execute a locator body inside the worker and return its JSON result."""
    source = DECODER + "\n" + body
    wrapper = (
        'def main():\n import traceback, json\n ns = {"values": ' + repr(values or {}) + "}\n"
        " try:\n  exec(" + json.dumps(source) + ',ns)\n  return json.dumps(ns["result"])\n'
        ' except Exception:\n  return json.dumps({"error": traceback.format_exc()[-1500:]})\nmain()'
    )
    payload = parse_mcp_result(await session.call_tool("py_eval", {"code": wrapper}))
    if not isinstance(payload, dict):
        return {"error": f"unexpected walk payload: {payload!r}"}
    return payload


async def owner_context(session, owner_ea, image_base, func_name):
    """Build the revalidated owner record ``write_located_globals`` expects."""
    function = await _inspect_function_via_mcp(session, int(owner_ea), image_base, func_name)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session, int(owner_ea), image_base, func_name, allow_across_function_boundary=True
        )
        allow_across = bool(function and function.get("func_sig"))
    if not function or not function.get("func_sig"):
        return None
    try:
        if int(function["func_va"], 0) != int(owner_ea):
            return None
        owner_end = int(owner_ea) + int(function["func_size"], 0)
    except (KeyError, TypeError, ValueError):
        return None
    return {
        "function": function,
        "owner_ea": int(owner_ea),
        "owner_end": owner_end,
        "allow_across": allow_across,
    }


def func_payload(function):
    """Project an inspected function onto the func artifact field set."""
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    return payload


async def inspect_func(session, ea, image_base, func_name):
    """Inspect a located function, retrying across a function boundary."""
    function = await _inspect_function_via_mcp(session, int(ea), image_base, func_name)
    if function:
        return func_payload(function)
    function = await _inspect_function_via_mcp(
        session, int(ea), image_base, func_name, allow_across_function_boundary=True
    )
    if not function:
        return None
    function["func_sig_allow_across_function_boundary"] = True
    return func_payload(function)
