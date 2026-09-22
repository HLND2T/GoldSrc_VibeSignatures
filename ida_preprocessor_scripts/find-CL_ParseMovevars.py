#!/usr/bin/env python3
"""Locate CL_ParseMovevars and the movevars global it fills.

``svc_newmovevars`` (opcode 44) is the client parse-table entry. Its handler is
the one-call wrapper ``CL_Parse_NewMoveVars``; the body that reads the message
into ``movevars`` is ``CL_ParseMovevars``. GoldSrc and HL25 compile that wrapper
as a 5-byte ``jmp``. CoF uses a framed ``call`` / ``ret``. SvEngine Linux keeps
a PIC wrapper and, on 8948, routes the call through the PLT.

The body is identified by the two cvar updates it owns, ``gl_zmax`` and
``gl_wateramp``, together with the ``movevars_t`` store shape from
``pm_shared/pm_movevars.h``: sixteen consecutive floats at +0 (gravity through
waveHeight) and eight more at +0x64 (rollangle through skyvec_z). The global
address is the base of that shape. On absolute builds the anchor instruction is
``fstp dword ptr [movevars.gravity]``. SvEngine Linux materializes the base in
``esi`` first: 10257 ``lea esi, [ebx+GOTOFF]``, 8948 ``mov esi, [ebx+GOT]`` whose
slot's pointee is ``movevars``. Both are register-relative disp32 accesses, so
the ordinary PIC addend recovers the object rather than the GOT slot.

A bare string xref is not enough on hl-3248..hl-8684 Windows: the ``jmp`` target
is only a ``loc_`` until this walk creates the function. The shared owner
recovery follows ``call`` and misses that ``jmp``.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    owner_context,
    run_walk,
)

FUNC_NAME = "CL_ParseMovevars"
GV_NAME = "movevars"
SERVICE_NAME = "svc_newmovevars"
# gravity..waveHeight, then rollangle..skyvec_z. footsteps and skyName sit between them.
MOVEVARS_OFFSETS = tuple(range(0, 0x40, 4)) + tuple(range(0x64, 0x84, 4))
WRAPPER_MAX_BYTES = 0x30
ADDRESS_MNEMONICS = frozenset({"fstp", "lea", "mov"})

WALK = r"""
def _text(value):
    if isinstance(value, bytes):
        return value.decode('latin1')
    return value


def service_handler(table, service):
    matches = []
    for index in range(80):
        entry = int(table) + index * 12
        opcode = int(ida_bytes.get_dword(entry))
        if opcode & 0xFF == 0xFF:
            break
        if opcode != index:
            return None
        name = _text(ida_bytes.get_strlit_contents(ida_bytes.get_dword(entry + 4), -1, ida_nalt.STRTYPE_C))
        if name != service:
            continue
        target = int(ida_bytes.get_dword(entry + 8))
        if is_code_address(target):
            matches.append(target)
    return matches[0] if len(matches) == 1 else None


def decoded(ea):
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, int(ea)) and not ida_ua.create_insn(int(ea)):
        return None, None
    if not ida_ua.decode_insn(insn, int(ea)):
        return None, None
    return (idc.print_insn_mnem(int(ea)) or '').lower(), insn


def ensure_function(ea):
    ea = int(ea)
    if not is_code_address(ea):
        return None
    function = ida_funcs.get_func(ea)
    if function is not None:
        return ea if int(function.start_ea) == ea else None
    flags = ida_bytes.get_full_flags(ea)
    if not (ida_bytes.is_code(flags) or ida_bytes.is_unknown(flags)):
        return None
    ida_funcs.add_func(ea)
    function = ida_funcs.get_func(ea)
    if function is None or int(function.start_ea) != ea:
        return None
    return ea


def real_callees(start):
    found = []
    for target in direct_calls(int(start)):
        callee = ida_funcs.get_func(int(target))
        if callee is None or int(callee.end_ea) - int(callee.start_ea) <= 8:
            continue
        name = (idc.get_func_name(int(target)) or '').lower()
        if 'thunk' in name or name.startswith('__x86'):
            continue
        found.append(int(target))
    return found


def unwrap(ea, depth=0):
    if depth > 4:
        return None
    mnem, insn = decoded(ea)
    if mnem == 'jmp' and insn is not None and int(insn.ops[0].type) == int(idaapi.o_near):
        dest = int(idc.get_operand_value(int(ea), 0))
        if dest != int(ea) and is_code_address(dest):
            return unwrap(dest, depth + 1)
    start = ensure_function(ea)
    if start is None:
        return None
    function = ida_funcs.get_func(start)
    if int(function.end_ea) - start > int(values['wrapper_max']):
        return start
    callees = real_callees(start)
    if len(callees) == 1 and callees[0] != start:
        return unwrap(callees[0], depth + 1)
    return start


def references_literal(start, literal):
    owner = ida_funcs.get_func(int(start))
    if owner is None or int(owner.start_ea) != int(start):
        return False
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    for item in strings:
        if str(item) != literal:
            continue
        for ref in idautils.XrefsTo(int(item.ea), 0):
            if int(owner.start_ea) <= int(ref.frm) < int(owner.end_ea):
                return True
    return False


handler = service_handler(values['table'], values['service'])
owner = None if handler is None else unwrap(handler)
if handler is None:
    result = {'error': 'svc_newmovevars handler is not a single code pointer'}
elif owner is None:
    result = {'error': 'svc_newmovevars wrapper does not resolve to one function', 'handler': hex(int(handler))}
elif not references_literal(owner, 'gl_zmax') or not references_literal(owner, 'gl_wateramp'):
    result = {'error': 'resolved body does not reference gl_zmax and gl_wateramp', 'owner_ea': hex(int(owner))}
else:
    entries = scan(owner)
    mapping = None if entries is None else single_globals(entries)
    offsets = tuple(int(value) for value in values['offsets'])
    bases = [] if mapping is None else [
        gv for gv in sorted(mapping) if all(gv + offset in mapping for offset in offsets)
    ]
    entry = None if len(bases) != 1 else first_addressable(entries, mapping[bases[0]])
    if entries is None:
        result = {'error': 'CL_ParseMovevars is not a function start', 'owner_ea': hex(int(owner))}
    elif len(bases) != 1:
        result = {'error': 'movevars_t store shape is not unique', 'owners': [hex(int(item)) for item in bases]}
    elif entry is None or entry['mnem'] not in values['mnemonics']:
        result = {'error': 'movevars base has no fstp/lea/mov displacement', 'owner_ea': hex(int(owner))}
    else:
        result = {
            'pointer_size': 4,
            'handler': hex(int(handler)),
            'owner_ea': hex(int(owner)),
            'gv': access(entry, bases[0]),
        }
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
    if _output_for_symbol(expected_outputs, FUNC_NAME) is None or _output_for_symbol(expected_outputs, GV_NAME) is None:
        return False
    table = _load_yaml_mapping(f"{new_binary_dir}/cl_parsefuncs.{platform}.yaml")
    if not table or "gv_va" not in table:
        return False
    located = await run_walk(
        session,
        WALK,
        {
            "table": int(table["gv_va"], 0),
            "service": SERVICE_NAME,
            "offsets": list(MOVEVARS_OFFSETS),
            "wrapper_max": WRAPPER_MAX_BYTES,
            "mnemonics": sorted(ADDRESS_MNEMONICS),
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    owner_ea = int(located["owner_ea"], 0)
    function = await inspect_func(session, owner_ea, image_base, FUNC_NAME)
    owner = await owner_context(session, owner_ea, image_base, FUNC_NAME)
    if not function or owner is None:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {owner_ea:#x}")
        return False
    if not await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]}
    ):
        if debug:
            print(f"{skill_name}: could not validate {GV_NAME} at {located['gv']}")
        return False
    write_func_yaml(_output_for_symbol(expected_outputs, FUNC_NAME), function)
    if debug:
        print(
            f"{skill_name}: handler={located.get('handler')} {FUNC_NAME}={owner_ea:#x} "
            f"{GV_NAME}={located['gv']['gv_ea']} via {located['gv'].get('insn_disasm')}"
        )
    return True
