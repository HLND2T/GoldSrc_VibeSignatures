#!/usr/bin/env python3
"""Recover realtime from the verified Host_Init body.

``engine/host.c`` declares ``double realtime`` and Host_Init writes
``realtime = 0`` while seeding the host globals. MetaHookSv instead arms on a
per-engine-family byte pattern (an ``fld``/``movsd`` feeding a nearby
``push 60h``), which is not a unique anchor here.

The reproducible invariant is the zero store itself: inside Host_Init exactly
one aligned, eight-byte writable global is written with a zero source. The five
shipped encodings are an SSE pair (``xorps xmm0,xmm0`` then ``movsd``), an x87
``fldz`` then ``fstp``, a register pair (``xor r,r`` then two ``mov``s over
``gv``/``gv+4``), and a stack slot later copied by a callee over ``gv``/``gv+4``.
The finder additionally requires the candidate to be read by many functions
outside Host_Init, which is what separates ``realtime`` from the handful of
write-only flags Host_Init also clears. It fails closed unless the candidate is
unique. No LLM step and no byte signature participate in discovery.
"""

from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

OWNER_NAME = "Host_Init"
GV_NAME = "realtime"
SCAN_ORDER = 90
MIN_EXTERNAL_READERS = 8

WALK = r"""
import ida_bytes, ida_funcs, ida_idp, ida_segment, ida_ua, idaapi, idautils

owner = int(values['owner'], 0)
order = int(values['order'])
min_readers = int(values['min_readers'])


def reg4(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def issmall(ea):
    return int(ida_bytes.get_item_size(int(ea))) < 8


def writes_register(insn, name):
    for index, op in enumerate(insn.ops[:1]):
        if int(op.type) == int(idaapi.o_reg) and reg4(op) == name:
            return True
    return False


def external_readers(gv):
    found = set()
    for xref in idautils.XrefsTo(int(gv), 0):
        function = ida_funcs.get_func(int(xref.frm))
        if function is not None and int(function.start_ea) != owner:
            found.add(int(function.start_ea))
    return found


entries = scan(owner)
if entries is None:
    result = {'error': 'Host_Init artifact is not a function start'}
else:
    zero_registers = set()
    x87_zero = False
    sse_zero = False
    full_bases = {}
    half_addresses = {}
    for entry in entries[:order]:
        insn = entry['insn']
        mnem = entry['mnem']
        source = insn.ops[1] if len(insn.ops) > 1 else None
        source_kind = int(source.type) if source is not None else int(idaapi.o_void)

        # A call preserves only callee-saved registers, so a zero tracked in
        # eax/ecx/edx/... is gone while ebx/esi/edi/ebp keep theirs.
        if mnem == 'call':
            zero_registers -= {'eax', 'ecx', 'edx'}
            x87_zero = False
            sse_zero = False
        elif mnem in ('ret', 'retn') or mnem.startswith('j'):
            zero_registers = set()
            x87_zero = False
            sse_zero = False

        if mnem == 'fldz':
            x87_zero = True
        elif mnem in ('fld', 'fstp', 'fst', 'faddp', 'fsubp', 'fmulp', 'fdivp'):
            if mnem != 'fstp' or not x87_zero:
                x87_zero = False

        if mnem in ('xorps', 'xorpd', 'pxor'):
            if 'xmm0' in (entry['disasm'] or ''):
                sse_zero = True
        elif source_kind == int(idaapi.o_reg) and reg4(source) == 'xmm0' and mnem != 'movsd':
            sse_zero = False

        zero_name = None
        if mnem == 'xor' and len(insn.ops) > 1 and source_kind == int(idaapi.o_reg):
            if int(insn.ops[0].type) == int(idaapi.o_reg) and int(insn.ops[0].reg) == int(source.reg):
                zero_name = reg4(insn.ops[0])
        elif mnem == 'mov' and source_kind == int(idaapi.o_imm) and int(source.value) == 0:
            if int(insn.ops[0].type) == int(idaapi.o_reg):
                zero_name = reg4(insn.ops[0])
        if zero_name is not None:
            zero_registers.add(zero_name)

        if entry['written']:
            for gv in entry['written']:
                gv = int(gv)
                if issmall(gv):
                    continue
                size = int(ida_bytes.get_item_size(gv))
                zero_source = False
                if mnem in ('movsd', 'movq', 'movlps') and source_kind == int(idaapi.o_reg):
                    zero_source = reg4(source) == 'xmm0' and sse_zero
                elif mnem == 'fstp':
                    zero_source = x87_zero
                elif mnem == 'mov' and source_kind == int(idaapi.o_reg):
                    zero_source = reg4(source) in zero_registers
                elif mnem == 'mov' and source_kind == int(idaapi.o_imm):
                    zero_source = int(source.value) == 0
                if not zero_source:
                    continue
                if size == 8 and gv % 8 == 0:
                    full_bases.setdefault(gv, entry)
                else:
                    half_addresses.setdefault(gv, entry)

        # Register write-back after the store check keeps the current store valid.
        if mnem == 'mov' and int(insn.ops[0].type) == int(idaapi.o_reg) and source_kind != int(idaapi.o_void):
            name = reg4(insn.ops[0])
            if name is not None and name not in zero_registers:
                pass
            elif name is not None and mnem != 'xor':
                zero_registers.discard(name)

    pair_bases = {}
    for gv, entry in half_addresses.items():
        if gv % 8:
            continue
        if gv + 4 in half_addresses:
            pair_bases[gv] = entry

    candidates = dict(pair_bases)
    for gv, entry in full_bases.items():
        candidates.setdefault(gv, entry)

    qualified = {}
    if len(candidates) == 1:
        gv, entry = next(iter(candidates.items()))
        qualified[gv] = (entry, len(external_readers(gv)))
    else:
        # Many write-only flags share the zero-store shape; realtime is the one
        # the rest of the engine reads. PIC builds hide those reads behind a GOT
        # slot, so the filter only runs when the shape alone is ambiguous.
        for gv, entry in candidates.items():
            readers = external_readers(gv)
            if len(readers) >= min_readers:
                qualified[gv] = (entry, len(readers))
    if len(qualified) != 1:
        result = {'error': 'realtime zero store is not unique',
                  'candidates': [{'gv': hex(g), 'readers': len(external_readers(g))}
                                 for g in sorted(candidates)]}
    else:
        gv, (entry, readers) = next(iter(qualified.items()))
        located = access(entry, gv)
        if located is None:
            result = {'error': 'no addressable realtime reference'}
        else:
            result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located,
                      'readers': readers}
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
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: missing or invalid {OWNER_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK,
        {"owner": hex(owner["owner_ea"]), "order": SCAN_ORDER, "min_readers": MIN_EXTERNAL_READERS},
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]})
