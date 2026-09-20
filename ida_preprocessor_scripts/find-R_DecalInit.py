#!/usr/bin/env python3
"""Locate ``R_DecalInit`` and the decal pool/cache globals it initializes.

``engine/gl_rsurf.c`` keeps the decal state in two file-scope arrays: ::

    static decal_t      gDecalPool[ MAX_DECALS ];        // 4096 * 28 = 0x1C000
    decalcache_t        gDecalCache[ DECAL_CACHEENTRY ];//  256 * 116 = 0x7400

    void R_DecalInit( void )
    {
        Q_memset( gDecalPool, 0, sizeof( decal_t ) * MAX_DECALS );
        gDecalCount = 0;
        for( i = 0; i < DECAL_CACHEENTRY; i++ )
            gDecalCache[i].decalIndex = -1;
    }

``R_DecalInit`` owns no literal, so it is located by two code signatures that cover every
configured engine family (see the find-anchor-to-goldsrc-symbol coverage budget):

* ``C7 00 FF FF FF FF 83 C0 74`` -- ``mov dword ptr [eax], -1 ; add eax, 74h``. This is the
  ``gDecalCache[i].decalIndex = -1`` statement together with the ``sizeof(decalcache_t)``
  stride, and it is unique on every configured Linux build and on ten of the eleven Windows
  builds.
* ``68 00 C0 01 00 6A 00`` -- ``push 1C000h ; push 0``. This is the ``Q_memset`` size/fill
  argument pair (``sizeof(decal_t) * MAX_DECALS``), emitted by MSVC on every Windows build,
  including cof-5936 whose cache loop is indexed instead of pointer-walked.

The two globals are then recovered from the located body rather than by address:

* ``gDecalCache`` is the array base of the ``-1`` store: the address loaded into the store's
  base register (``mov reg, offset X`` / PIC ``lea reg, (X - GOT)[ebx]``), or the absolute
  displacement of an indexed store (cof-5936).
* ``gDecalPool`` is the destination the body's single non-thunk call (``Q_memset``) zeroes.

Linux evidence for the emitted addresses: the retained ELF symbol tables give ``gDecalPool``
``0x807ba0`` / ``gDecalCache`` ``0xf9f820`` (hl-10210) and ``0x796d060`` / ``0x38d80a0``
(svencoop-8948), both arrays exactly ``0x1c000`` / ``0x7400`` bytes.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    func_payload,
    owner_context,
    run_walk,
)

TARGET_FUNCTION_NAME = "R_DecalInit"
TARGET_GLOBAL_NAMES = ("gDecalPool", "gDecalCache")

# Source statement: `gDecalCache[i].decalIndex = -1` plus the decalcache_t stride.
SIGNATURE_LOOP_STORE = "C700FFFFFFFF83C074"
# Source statement: `Q_memset(gDecalPool, 0, sizeof(decal_t) * MAX_DECALS)` argument pair.
SIGNATURE_POOL_MEMSET = "6800C001006A00"
SIGNATURE_ORDER = (
    ("loop_store", SIGNATURE_LOOP_STORE),
    ("pool_memset", SIGNATURE_POOL_MEMSET),
)

# Instructions scanned backwards from the memset call for its destination operand.
POOL_LOOKBACK = 8

LOCATE_BODY = r"""
def signature_owners():
    def owner_start(ea):
        function = ida_funcs.get_func(int(ea))
        return None if function is None else int(function.start_ea)

    def all_matches(pattern):
        hits = []
        ea = int(idaapi.inf_get_min_ea())
        max_ea = int(idaapi.inf_get_max_ea())
        while ea < max_ea:
            found = ida_bytes.find_bytes(pattern, ea, max_ea)
            if found is None or found == idaapi.BADADDR:
                break
            hits.append(int(found))
            ea = int(found) + 1
        return hits

    for label, signature in values["signatures"]:
        hits = all_matches(bytes.fromhex(signature))
        if not hits:
            continue
        owners = {owner_start(hit) for hit in hits}
        if None in owners or len(owners) != 1:
            return {"error": "code signature does not resolve to exactly one owning function",
                    "signature": label, "match_count": len(hits)}
        return {"owner_ea": hex(owners.pop()), "signature": label, "match_count": len(hits)}
    return {"error": "no code signature resolves to a single decal-init function"}


# Writable-data addresses an instruction names as an address (immediate, absolute
# memory operand, or a tracked PIC base plus displacement).
def named_globals(ea, insn, bases):
    found = set()
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) == int(idaapi.o_mem):
            if is_writable_data(int(op.addr)) and not is_got(int(op.addr)):
                found.add(int(op.addr))
        elif int(op.type) == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
            if is_writable_data(value) and not is_got(value):
                found.add(value)
        elif int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            base = reg4(op)
            if base in bases:
                resolved = (int(bases[base]) + signed32(op.addr)) & 0xFFFFFFFF
                if is_writable_data(resolved) and not is_got(resolved):
                    found.add(resolved)
            elif int(op.addr) and is_writable_data(int(op.addr) & 0xFFFFFFFF):
                # Absolute displacement inside an indexed operand, e.g. cof-5936's
                # `mov dword_2BFE2C0[ecx], 0FFFFFFFFh`.
                found.add(int(op.addr) & 0xFFFFFFFF)
    return found


def locate_globals(start):
    function = ida_funcs.get_func(int(start))
    if function is None:
        return {"error": "signature owner is not a function"}

    bases = {}
    got_base, got_register = got_anchor(int(start))
    if got_base is not None:
        bases[got_register] = got_base

    register_globals = {}
    register_refs = {}
    entries = []
    cache_stores = []
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if insn is None:
            continue
        mnemonic = (idc.print_insn_mnem(int(ea)) or '').lower()
        entry = {
            "ea": int(ea),
            "len": int(insn.size),
            "disp": disp32_offset(insn),
            "disasm": idc.generate_disasm_line(int(ea), 0) or '',
            "globals": named_globals(ea, insn, bases),
        }
        if len(insn.ops) > 1 and mnemonic in ('mov', 'and', 'or'):
            destination = insn.ops[0]
            immediate_ones = {
                int(op.value) & 0xFFFFFFFF for op in insn.ops if int(op.type) == int(idaapi.o_imm)
            }
            if (int(destination.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))
                    and 0xFFFFFFFF in immediate_ones and entry["disp"]):
                base_register = reg4(destination)
                if base_register in register_globals:
                    cache_stores.append((register_globals[base_register], register_refs[base_register]))
                elif int(getattr(destination, 'addr', 0) or 0):
                    absolute = int(destination.addr) & 0xFFFFFFFF
                    if is_writable_data(absolute):
                        cache_stores.append((absolute, entry))
        entries.append(entry)

        # Track the register that currently holds one address-loaded global.
        if int(insn.ops[0].type) == int(idaapi.o_reg) and mnemonic not in ('push', 'pop'):
            target = reg4(insn.ops[0])
            source = insn.ops[1] if len(insn.ops) > 1 else None
            if mnemonic == 'mov' and source is not None and int(source.type) == int(idaapi.o_reg):
                next_global = register_globals.get(reg4(source))
                next_ref = register_refs.get(reg4(source))
            elif mnemonic in ('mov', 'lea') and len(entry["globals"]) == 1:
                next_global = next(iter(entry["globals"]))
                next_ref = entry
            else:
                next_global = None
                next_ref = None
            if next_global is None:
                register_globals.pop(target, None)
                register_refs.pop(target, None)
            else:
                register_globals[target] = next_global
                register_refs[target] = next_ref

    if len(cache_stores) != 1:
        return {"error": "expected exactly one qualifying gDecalCache store",
                "store_count": len(cache_stores)}
    cache, cache_ref = cache_stores[0]

    memset_sites = []
    for callee, sites in direct_calls(int(start)).items():
        callee_function = ida_funcs.get_func(int(callee))
        if callee_function is None:
            continue
        if int(callee_function.end_ea) - int(callee_function.start_ea) <= 4:
            # PIC `__x86.get_pc_thunk.*` prologue helper.
            continue
        memset_sites.extend(int(site) for site in sites)
    if len(memset_sites) != 1:
        return {"error": "expected exactly one non-thunk call in the decal-init body",
                "call_count": len(memset_sites)}
    memset_site = memset_sites[0]
    index = next((i for i, entry in enumerate(entries) if entry["ea"] == memset_site), None)
    if index is None:
        return {"error": "memset call is not part of the decoded body"}

    pool = None
    pool_ref = None
    for prior in reversed(entries[max(0, index - int(values["pool_lookback"])):index]):
        candidates = prior["globals"] - {cache}
        if len(candidates) > 1:
            return {"error": "ambiguous gDecalPool scan window",
                    "candidates": sorted(hex(value) for value in candidates)}
        if len(candidates) == 1 and prior["disp"]:
            pool = next(iter(candidates))
            pool_ref = prior
            break
    if pool is None or pool_ref is None:
        return {"error": "gDecalPool memset destination not recovered"}

    return {
        "owner_ea": hex(int(function.start_ea)),
        "gDecalPool": {
            "gv_ea": hex(pool),
            "insn_ea": hex(pool_ref["ea"]),
            "insn_len": hex(pool_ref["len"]),
            "insn_disp": hex(pool_ref["disp"]),
            "insn_disasm": pool_ref["disasm"],
        },
        "gDecalCache": {
            "gv_ea": hex(cache),
            "insn_ea": hex(cache_ref["ea"]),
            "insn_len": hex(cache_ref["len"]),
            "insn_disp": hex(cache_ref["disp"]),
            "insn_disasm": cache_ref["disasm"],
        },
    }


located = signature_owners()
if not located.get("error"):
    globals_payload = locate_globals(int(located["owner_ea"], 0))
    if globals_payload.get("error"):
        located = globals_payload
    else:
        located.update(globals_payload)
result = located
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
    if platform not in {"windows", "linux"}:
        return False
    function_output = _output_for_symbol(expected_outputs, TARGET_FUNCTION_NAME)
    if function_output is None:
        return False
    if any(_output_for_symbol(expected_outputs, name) is None for name in TARGET_GLOBAL_NAMES):
        return False

    located = await run_walk(
        session,
        LOCATE_BODY,
        {
            "signatures": [[label, signature] for label, signature in SIGNATURE_ORDER],
            "pool_lookback": POOL_LOOKBACK,
        },
    )
    if located.get("error"):
        if debug:
            print(f"{skill_name}: {located['error']}")
        return False

    try:
        owner_ea = int(located["owner_ea"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    owner = await owner_context(session, owner_ea, image_base, TARGET_FUNCTION_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: could not revalidate {TARGET_FUNCTION_NAME} at {owner_ea:#x}")
        return False

    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {name: located[name] for name in TARGET_GLOBAL_NAMES},
    ):
        return False
    write_func_yaml(function_output, func_payload(owner["function"]))

    if debug:
        print(
            f"{skill_name}: {TARGET_FUNCTION_NAME} at {owner_ea:#x} "
            f"(signature {located.get('signature')}, {located.get('match_count')} match(es)); "
            + " ".join(f"{name}={located[name]['gv_ea']}" for name in TARGET_GLOBAL_NAMES)
        )
    return True
