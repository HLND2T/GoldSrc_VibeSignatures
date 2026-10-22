#!/usr/bin/env python3
"""Resolve Issue #395's consumer aliases from Sven 5.15/5.16 server evidence.

Discovery uses current-image RTTI vtables and the Grapple classifier's own
classname literals, never old artifacts, byte signatures or entity creation.
The five old slot indices were checked independently on all four x86 images.
Emit ordinary function records: ASExtHook hooks the actual entry, including
inherited entries, rather than resolving a virtual dispatch slot at runtime.

Verified implementation mapping (both versions/platforms):
  ApacheTraceAttack       CApache::TraceAttack
  OspreyTraceAttack       COsprey::TraceAttack
  TurretTraceAttack       CTurret -> CBaseTurret::TraceAttack
  BreakableTraceAttack    CBreakable::TraceAttack
  BreakableTakeDamage     CBreakable::TakeDamage (retain the ELF wrapper)
  BreakableKilled         CBreakable -> CBaseEntity::Killed
  BaseMonsterTraceAttack  CBloater -> CBaseMonster::TraceAttack
  PlayerPostTakeDamage    CBasePlayer::TakeDamage (no separate post function)
  PlayerTakeHealth       CBasePlayer::TakeHealth (overrides CBaseMonster)
  IRelationship          CBasePlayer -> CBaseEntity::IRelationship
GrappleGetMonsterType is the classifier called by CBarnacleGrappleTongue.

Windows methods use ECX=this and callee cleanup. TraceAttack's explicit stack
arguments are attacker, damage, Vector's three floats, trace, damageType (28
bytes). Linux uses cdecl with explicit stack this; Vector is passed through a
pointer to the caller's by-value temporary (six 4-byte machine arguments).
TakeDamage has two entvars pointers, float, int; TakeHealth has float, int, int;
Killed has entvars pointer, int; IRelationship has entity pointer, bool (one
stack word, low byte used). Integer results use EAX; TraceAttack/Killed are void.
Grapple uses ECX plus one stack entity on Windows (this unused by the body),
two stack words on Linux; returns 1 for small monsters, 4 for tentacle, else 2.
"""

from pathlib import Path

from ida_analyze_util import (
    preprocess_func_xrefs_via_mcp,
    preprocess_vtable_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._vgui_private_symbols_common import function_payload

# alias, entity class, slot, Windows explicit stack bytes
TARGETS = (
    ("ApacheTraceAttack", "CApache", 20, 28),
    ("OspreyTraceAttack", "COsprey", 20, 28),
    ("TurretTraceAttack", "CTurret", 20, 28),
    ("BreakableTraceAttack", "CBreakable", 20, 28),
    ("BreakableTakeDamage", "CBreakable", 21, 16),
    ("BreakableKilled", "CBreakable", 24, 8),
    ("BaseMonsterTraceAttack", "CBloater", 20, 28),
    ("PlayerPostTakeDamage", "CBasePlayer", 21, 16),
    ("PlayerTakeHealth", "CBasePlayer", 22, 12),
    ("IRelationship", "CBasePlayer", 17, 8),
)
INHERITED = (
    ("CTurret", "CBaseTurret", 20),
    ("CBreakable", "CBaseEntity", 24),
    ("CBloater", "CBaseMonster", 20),
    ("CBasePlayer", "CBaseEntity", 17),
)
GRAPPLE = "GrappleGetMonsterType"
GRAPPLE_LITERALS = ("monster_babycrab", "monster_stukabat", "monster_tentacle")

VERIFY = r"""
import idaapi, ida_funcs, ida_bytes, ida_segment, idautils, idc, json
assert not idaapi.inf_is_64bit(), 'Sven server requires x86'
evidence = {}
for name, ea, cleanup in values['functions']:
    f = ida_funcs.get_func(ea)
    seg = ida_segment.getseg(ea)
    assert f and f.start_ea == ea and f.size() > 0, (name, 'not a complete function')
    assert seg and seg.perm & ida_segment.SEGPERM_EXEC, (name, 'not executable')
    returns = set()
    for insn_ea in idautils.FuncItems(ea):
        if idc.print_insn_mnem(insn_ea) not in ('ret', 'retn'):
            continue
        insn = idautils.DecodeInstruction(insn_ea)
        returns.add(int(insn.ops[0].value) if insn.ops[0].type == idaapi.o_imm else 0)
    assert returns == {cleanup}, (name, 'unexpected return cleanup', sorted(returns), cleanup)
    evidence[name] = dict(ea=ea, size=f.size(), cleanup=cleanup)
paths = {values['grapple']: [values['grapple']]}
frontier = set(paths)
roots = set(values['tongue_entries'])
proof = None
# Think/touch callbacks are ordinary members, so include code-owned data refs
# to callback addresses as well as direct calls. Bound the ownership walk.
for depth in range(4):
    following = set()
    for target in frontier:
        for ref in idautils.XrefsTo(target):
            owner = ida_funcs.get_func(ref.frm)
            if not owner or owner.start_ea in paths:
                continue
            paths[owner.start_ea] = [owner.start_ea] + paths[target]
            following.add(owner.start_ea)
            if owner.start_ea in roots:
                proof = paths[owner.start_ea]
    if proof:
        break
    frontier = following
assert proof, 'classifier is not reachable from Grapple tongue methods'
evidence['GrappleGetMonsterType']['tongue_call_path'] = proof
result = evidence
"""


def entry(table, index):
    entries = table["vtable_entries"]
    value = entries.get(index, entries.get(str(index)))
    return int(value, 0) if isinstance(value, str) else int(value)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    try:
        classes = sorted({t[1] for t in TARGETS} | {t[1] for t in INHERITED} | {"CBarnacleGrappleTongue"})
        tables = {}
        for cls in classes:
            table = await preprocess_vtable_via_mcp(session, cls, image_base, platform)
            if not table:
                raise ValueError(f"Missing unambiguous current-image RTTI vtable: {cls}")
            tables[cls] = table
        for derived, base, index in INHERITED:
            if entry(tables[derived], index) != entry(tables[base], index):
                raise ValueError(f"Changed inheritance: {derived} -> {base}, slot {index}")
        if entry(tables["CBasePlayer"], 22) == entry(tables["CBaseMonster"], 22):
            raise ValueError("Player TakeHealth no longer overrides the monster implementation")

        grapple = await preprocess_func_xrefs_via_mcp(
            session=session,
            func_name=GRAPPLE,
            xref_strings=["FULLMATCH:" + text for text in GRAPPLE_LITERALS],
            xref_gvs=[],
            xref_signatures=[],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
        )
        if not grapple:
            raise ValueError("Grapple classname intersection is not a unique function")
        addresses = {name: entry(tables[cls], index) for name, cls, index, _ in TARGETS}
        addresses[GRAPPLE] = int(grapple["func_va"], 0)
        functions = [
            (name, addresses[name], cleanup if platform == "windows" else 0) for name, _, _, cleanup in TARGETS
        ]
        functions.append((GRAPPLE, addresses[GRAPPLE], 4 if platform == "windows" else 0))
        values = {
            "functions": functions,
            "grapple": addresses[GRAPPLE],
            "tongue_entries": [
                entry(tables["CBarnacleGrappleTongue"], i) for i in tables["CBarnacleGrappleTongue"]["vtable_entries"]
            ],
        }
        result = await run_walk(session, VERIFY, values)
        if not isinstance(result, dict) or set(result) != set(addresses):
            raise ValueError(f"Current-image ABI verification failed: {result}")

        outputs = {Path(p).name.removesuffix(f".{platform}.yaml"): p for p in expected_outputs}
        if len(outputs) != len(expected_outputs) or set(outputs) != set(addresses):
            raise ValueError("Expected output inventory differs from the 11 consumer aliases")
        payloads = {}
        for name, ea in addresses.items():
            payload = await function_payload(session, ea, image_base, name)
            if not payload:
                raise ValueError(f"Cannot generate a unique current-image signature: {name}")
            payloads[name] = payload
        for name, payload in payloads.items():
            write_func_yaml(outputs[name], payload)
        if debug:
            print(f"ASExtHook verified entries and ABI: {result}")
        return True
    except (AssertionError, KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"ASExtHook server locator rejected: {exc}")
        return False
