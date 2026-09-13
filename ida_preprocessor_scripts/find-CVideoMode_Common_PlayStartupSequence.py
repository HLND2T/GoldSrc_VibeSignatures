#!/usr/bin/env python3
"""Recover CVideoMode_Common_PlayStartupSequence from constructed VideoMode vtables.

HL25 (hl-10210) only. The ``-novid`` literal has two raw owners, so a plain
string xref cannot select it. This adapter starts from the covered
VideoMode_Create artifact, verifies its signature still resolves to the same
entry, then walks the vptr stores written by VideoMode_Create itself and by its
directly-called constructors. Each vptr value is resolved as a run of
consecutive valid code entries (GoldSrc vtable slots are four bytes); exactly
one member of these constructed VideoMode vtables references ``-novid``, which
is PlayStartupSequence (engine/vid_common.cpp). The slot index is never
hardcoded. Output stays the plain func contract.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNC_NAME = "CVideoMode_Common_PlayStartupSequence"
CREATE_FUNC_NAME = "VideoMode_Create"
NOVID_LITERAL = "-novid"
MAX_VTABLE_SLOTS = 512
MAX_CREATE_CALLEES = 64

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

CREATE_EA = CREATE_EA_PLACEHOLDER
NOVID_LITERAL = NOVID_LITERAL_PLACEHOLDER
MAX_VTABLE_SLOTS = MAX_VTABLE_SLOTS_PLACEHOLDER
MAX_CREATE_CALLEES = MAX_CREATE_CALLEES_PLACEHOLDER

def is_code_ea(ea):
    segment = ida_segment.getseg(int(ea))
    return bool(
        segment
        and int(getattr(segment, 'perm', 0)) & int(getattr(idaapi, 'SEGPERM_EXEC', 4))
    )

def function_start(ea):
    function = ida_funcs.get_func(int(ea))
    return int(function.start_ea) if function is not None else None

def direct_callees(start_ea):
    targets = set()
    function = ida_funcs.get_func(int(start_ea))
    if function is None:
        return targets
    for ea in idautils.FuncItems(int(function.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn or insn.get_canon_mnem() != 'call':
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_near):
                targets.add(int(op.addr))
    return targets

def vptr_store_values(start_ea):
    values = []
    function = ida_funcs.get_func(int(start_ea))
    if function is None:
        return values
    for ea in idautils.FuncItems(int(function.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn or insn.get_canon_mnem() != 'mov':
            continue
        ops = list(insn.ops)
        if len(ops) < 2:
            continue
        # mov [reg], imm32 : base displacement with an immediate source.
        if int(ops[0].type) not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            continue
        if int(ops[1].type) != int(idaapi.o_imm):
            continue
        imm = int(ops[1].value) & 0xFFFFFFFF
        if not imm or imm == 0xFFFFFFFF or is_code_ea(imm):
            continue
        # A vptr store targets a zero/short displacement (the object head or
        # an embedded member), not a large field offset.
        if int(getattr(ops[0], 'addr', 0)) > 0x40:
            continue
        values.append({'writer_ea': int(ea), 'vptr_value': imm})
    return values

def is_function_entry(ea):
    function = ida_funcs.get_func(int(ea))
    return function is not None and int(function.start_ea) == int(ea) and is_code_ea(ea)

def vtable_entries_from(vptr_value):
    entries = []
    cursor = int(vptr_value) & ~3
    for _ in range(int(MAX_VTABLE_SLOTS)):
        raw = ida_bytes.get_bytes(cursor, 4)
        if not raw or len(raw) != 4:
            break
        slot = int.from_bytes(raw, 'little')
        if not slot or not is_function_entry(slot):
            break
        entries.append(slot)
        cursor += 4
    return entries

def novid_owner_starts():
    owners = set()
    for item in idautils.Strings(default_setup=False):
        if str(item) != NOVID_LITERAL:
            continue
        for xref in idautils.XrefsTo(int(item.ea), 0):
            start = function_start(xref.frm)
            if start is not None:
                owners.add(start)
    return owners

def main():
    create_fn = ida_funcs.get_func(int(CREATE_EA))
    if create_fn is None or int(create_fn.start_ea) != int(CREATE_EA):
        return {'error': 'VideoMode_Create artifact entry is not a function start'}
    writers = {int(CREATE_EA)}
    for callee in sorted(direct_callees(int(CREATE_EA)))[: int(MAX_CREATE_CALLEES)]:
        writers.add(callee)
    stores = []
    for writer in sorted(writers):
        stores.extend(vptr_store_values(writer))
    if not stores:
        return {'error': 'no vptr store found in VideoMode_Create or its direct callees'}
    owners = novid_owner_starts()
    if not owners:
        return {'error': 'no function references the -novid literal'}
    matches = []
    seen_tables = set()
    for store in stores:
        vptr = store['vptr_value']
        if vptr in seen_tables:
            continue
        seen_tables.add(vptr)
        entries = vtable_entries_from(vptr)
        if not entries:
            continue
        for index, entry in enumerate(entries):
            if entry in owners:
                matches.append({
                    'writer_ea': hex(store['writer_ea']),
                    'vptr_value': hex(vptr),
                    'slot_index': index,
                    'sequence_va': hex(entry),
                })
    unique_targets = sorted({int(match['sequence_va'], 0) for match in matches})
    if len(unique_targets) != 1:
        return {
            'error': 'PlayStartupSequence candidates: %d' % len(unique_targets),
            'matches': matches,
            'novid_owners': [hex(value) for value in sorted(owners)],
        }
    return {
        'pointer_size': 4,
        'create_va': hex(int(CREATE_EA)),
        'writer_ea': matches[0]['writer_ea'],
        'vptr_value': matches[0]['vptr_value'],
        'slot_index': matches[0]['slot_index'],
        'novid_owners': [hex(value) for value in sorted(owners)],
        'sequence_va': matches[0]['sequence_va'],
    }

globals().update(locals())
try:
    if idaapi.inf_is_64bit():
        result = json.dumps({'error': 'expected 32-bit x86'})
    else:
        result = json.dumps(main())
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _create_artifact(new_binary_dir, platform):
    path = Path(new_binary_dir) / f"{CREATE_FUNC_NAME}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("func_name") != CREATE_FUNC_NAME:
        return None
    return artifact


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
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    if output is None:
        return False
    artifact = _create_artifact(new_binary_dir, platform)
    if artifact is None:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: missing {CREATE_FUNC_NAME} artifact")
        return False
    signature = artifact.get("func_sig")
    if not isinstance(signature, str) or not signature.strip():
        return False
    try:
        create_va = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if create_va < int(image_base):
        return False
    # The artifact signature must still resolve uniquely to the recorded
    # VideoMode_Create entry in the current database before any vtable walk.
    if await _find_unique_bytes(session, signature) != create_va:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: stale {CREATE_FUNC_NAME} signature")
        return False
    code = (
        LOCATE_PY.replace("CREATE_EA_PLACEHOLDER", str(int(create_va)))
        .replace("NOVID_LITERAL_PLACEHOLDER", repr(NOVID_LITERAL))
        .replace("MAX_VTABLE_SLOTS_PLACEHOLDER", str(MAX_VTABLE_SLOTS))
        .replace("MAX_CREATE_CALLEES_PLACEHOLDER", str(MAX_CREATE_CALLEES))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        payload = None
    if not isinstance(payload, dict) or payload.get("error") or payload.get("pointer_size") != 4:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: locator failed {payload}")
        return False
    try:
        sequence_va = int(payload["sequence_va"], 0)
    except (TypeError, ValueError):
        return False
    if sequence_va < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, sequence_va, image_base, TARGET_FUNC_NAME)
    if not function or not function.get("func_sig") or int(function["func_va"], 0) != sequence_va:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: failed to inspect {payload['sequence_va']}")
        return False
    if debug:
        print(
            f"  find-{TARGET_FUNC_NAME}: func={payload['sequence_va']} "
            f"vptr={payload['vptr_value']} slot={payload['slot_index']} "
            f"writers={payload['writer_ea']}"
        )
    write_func_yaml(
        output,
        {
            "func_name": TARGET_FUNC_NAME,
            "func_va": function["func_va"],
            "func_rva": function["func_rva"],
            "func_size": function["func_size"],
            "func_sig": function["func_sig"],
        },
    )
    return True
