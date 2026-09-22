#!/usr/bin/env python3
"""Recover cl_sf, the client_state_t screen-fade block, from R_PolyBlend.

``cl_sf`` is ``&cl.sf``: the ``screenfade_t`` member of the engine's global
``client_state_t cl``.  Official GoldSrc reads ``cl.sf.fadeFlags`` here:

    if (cl.sf.fadeFlags & FFADE_MODULATE)      // engine/gl_rmain.c:1059
        ... cl.sf.fader / fadeg / fadeb ...    // gl_rmain.c:1063-1075

so the member address is the absolute operand of that FFADE_MODULATE (bit 1)
test minus ``offsetof(screenfade_t, fadeFlags)`` (common/screenfade.h:20).

Two encodings of the same source statement exist and both are accepted;
exactly one candidate must remain in the whole function:

* ``test <mem>, 2``                     -- HL/SvEngine/CoF Windows, HL/SvEngine Linux
* ``mov <reg>, <mem>`` + ``and <reg>, 2`` -- CoF Windows only

The artifact is anchored on the instruction that encodes the four-byte operand:
the ``test`` itself, or the ``mov`` load for the register form (``and`` has no
displacement).  SvEngine Linux reaches the member through a GOT-derived base
(``mov esi, [got]; test byte ptr [esi+24275Ch], 2``); the shared
``_engine_private_globals_common`` decoder resolves that to the absolute object,
emitting ``gv_pic_addend`` instead of ``gv_address_offset``.

A current-IDB direct locator is used instead of an ``LLM_DECOMPILE`` predecessor
because the requested object is the *struct base*, while ``found_gv`` returns
the tested operand's own address (``fadeFlags``) and would silently emit a wrong
``gv_va``.  The same source invariant identifies the access on all 15 configured
engine targets (11 Windows + 4 Linux), where the derived address agrees with the
independently located ``cl_light_level`` by exactly ``0x34`` and with
``cl_waterlevel`` by exactly ``0x24`` (client.h:337-349 member order).

The predecessor ``R_PolyBlend`` is already covered for every configured engine
build; only its artifact is reused.  No reference YAML participates.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

OWNER_FUNC_NAME = "R_PolyBlend"
TARGET_GLOBAL_NAME = "cl_sf"
# common/screenfade.h: four floats, then fader/fadeg/fadeb/fadealpha, then fadeFlags.
FADEFLAGS_OFFSET = 20

WALK = r"""
import idaapi

OWNER_EA = int(values['owner'], 0)
FADEFLAGS_OFFSET = int(values['fade_flags_offset'])
entries = scan(OWNER_EA)
if entries is None:
    result = {'error': 'R_PolyBlend is not a function start'}
else:
    def operands(entry):
        return [op for op in entry['insn'].ops if int(op.type) != int(idaapi.o_void)]

    # ``test <mem>, 2`` and ``mov <reg>, <mem>`` + ``and <reg>, 2`` are the two
    # encodings of ``cl.sf.fadeFlags & FFADE_MODULATE`` seen in the shipped
    # engine builds.  The register form reuses the load that carries the operand.
    direct = []
    indirect = []
    loaded_globals = {}
    for entry in entries:
        if entry['mnem'] == 'call':
            # Calls can overwrite registers without an explicit destination operand.
            # Conservatively require a fresh load after any call.
            loaded_globals.clear()
            continue
        ops = operands(entry)
        if len(ops) == 2 and int(ops[1].type) == int(idaapi.o_imm) and int(ops[1].value) == 2:
            if entry['mnem'] == 'test' and len(entry['targets']) == 1:
                direct.append((entry, next(iter(entry['targets']))))
            elif entry['mnem'] == 'and' and int(ops[0].type) == int(idaapi.o_reg):
                source = loaded_globals.get(reg4(ops[0]))
                if source is not None:
                    indirect.append(source)
        if ops and int(ops[0].type) == int(idaapi.o_reg):
            name = reg4(ops[0])
            if entry['mnem'] == 'mov' and len(entry['targets']) == 1:
                loaded_globals[name] = (entry, next(iter(entry['targets'])))
            elif name in loaded_globals and changed_operand(entry['insn'], 0):
                loaded_globals.pop(name, None)
    candidates = direct + indirect
    if len(candidates) != 1:
        result = {'error': 'cl.sf FFADE_MODULATE test is not unique', 'count': len(candidates)}
    else:
        entry, fade_flags_ea = candidates[0]
        result = access(entry, fade_flags_ea - FADEFLAGS_OFFSET)
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
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_GLOBAL_NAME)
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml")
    if output is None or not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        return False
    try:
        owner_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if owner_ea < int(image_base):
        return False
    owner = await owner_context(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if owner is None:
        if debug:
            print(f"  {TARGET_GLOBAL_NAME}: missing or invalid {OWNER_FUNC_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK,
        {"owner": hex(owner_ea), "fade_flags_offset": FADEFLAGS_OFFSET},
    )
    if (
        not isinstance(located, dict)
        or located.get("error")
        or any(key not in located for key in ("gv_ea", "insn_ea", "insn_len", "insn_disp"))
    ):
        if debug:
            print(f"  {TARGET_GLOBAL_NAME}: locator failed {located}")
        return False
    if debug:
        print(
            f"  {TARGET_GLOBAL_NAME}: gv={located['gv_ea']} insn={located['insn_ea']} {located.get('insn_disasm', '')}"
        )
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {TARGET_GLOBAL_NAME: located},
    )
