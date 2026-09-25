#!/usr/bin/env python3
"""Locate the Sven Co-op client portal shader initialisation chain.

``ClientPortalManager::InitShader`` creates, compiles and links the portal
program, stores the shader-available flag and the program handle, and releases
the program when shaders become unavailable. ``EnableShader`` and
``DisableShader`` run it and then select the program (``glUseProgram(handle)`` /
``glUseProgram(0)``) through the GLEW entry point.

All three are recovered from the ClientPortalManager_DrawPortals artifact with a
deterministic instruction walk, so no byte signature and no LLM step
participates in discovery:

* ``InitShader`` is the unique function reachable within two call levels of
  DrawPortals that materialises both ``GL_VERTEX_SHADER`` (0x8B31) and
  ``GL_FRAGMENT_SHADER`` (0x8B30). Those immediates come from the two
  ``glCreateShader`` calls of the source body, so the rule encodes the function's
  own statement rather than a build identity.
* ``EnableShader`` / ``DisableShader`` are the functions that call ``InitShader``
  first, read the shader-available byte member under a zero comparison, and end
  in exactly one indirect branch to the GLEW ``glUseProgram`` slot. The one whose
  final argument is the immediate 0 is ``DisableShader``; the one that reloads
  the program member from the same ``this`` entry argument is ``EnableShader``.
  The per-build member displacements are read from the located wrappers, and the
  flag and handle displacements are then re-checked against InitShader's own
  stores, so no offset is hardcoded.

The wrappers exist standalone on the Linux builds only. MSVC inlines both into
DrawPortals, and svencoop-10257's GCC splits ``DisableShader`` into the
``InitShader`` call plus the shared ``glUseProgram(0)`` reset helper, so those
builds have no such function to name. The Windows bodies that the compiler kept
out of line are unreachable: nothing in either image calls or points at them,
and IDA does not define them as functions. The finder therefore emits only the
symbols that exist, and the per-gamever configs declare the matching subset.
"""

import json
from pathlib import Path

import ida_analyze_util as u
from ida_elf import ELF_RESOLVER_PY

INIT_NAME = "ClientPortalManager_InitShader"
ENABLE_NAME = "ClientPortalManager_EnableShader"
DISABLE_NAME = "ClientPortalManager_DisableShader"
PREDECESSOR = "ClientPortalManager_DrawPortals"
TARGETS = (INIT_NAME, ENABLE_NAME, DISABLE_NAME)

MARKER = "__I245_SHADERCHAIN__"
GL_VERTEX_SHADER = 0x8B31
GL_FRAGMENT_SHADER = 0x8B30
MAX_CALL_DEPTH = 2

WALK = (
    ELF_RESOLVER_PY
    + r"""
import ida_funcs, ida_idp, ida_segment, ida_ua, idautils, idc, json

MARKER = @@MARKER@@
PRED = @@PRED@@
VERTEX_SHADER = @@VERTEX_SHADER@@
FRAGMENT_SHADER = @@FRAGMENT_SHADER@@
MAX_CALL_DEPTH = @@MAX_CALL_DEPTH@@

O_REG, O_MEM, O_PHRASE, O_DISPL, O_IMM, O_NEAR = 1, 2, 3, 4, 5, 7
REG_ESP = 4
CALL_CLOBBERED = (0, 1, 2)  # eax, ecx, edx


def changes_operand(insn, index):
    return bool(insn.get_canon_feature() & getattr(ida_idp, "CF_CHG%d" % (index + 1)))


def writes_operand_zero(insn):
    # True when the instruction changes its first operand.
    return changes_operand(insn, 0)


def emit(payload):
    print(MARKER + json.dumps(payload))


def decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None


def items(f):
    return list(idautils.FuncItems(f))


def func_start(ea):
    function = ida_funcs.get_func(ea)
    return int(function.start_ea) if function else None


# A call target that is this module's own definition, never a PLT stub or thunk.
def local_target(ea):
    target = resolve_elf_plt(int(ea))
    segment = ida_segment.getseg(target)
    if segment is None or not (int(segment.perm) & ida_segment.SEGPERM_EXEC):
        return None
    if ida_segment.get_segm_name(segment).startswith(".plt"):
        return None
    function = ida_funcs.get_func(target)
    if function is None or int(function.start_ea) != target:
        return None
    if int(function.end_ea) - int(function.start_ea) <= 8:
        return None  # get_pc_thunk and other call-transparent helpers
    return target


def direct_callees(owner):
    targets = []
    for ea in items(owner):
        insn = decode(ea)
        if insn is None or insn.get_canon_mnem() != "call" or int(insn.ops[0].type) != O_NEAR:
            continue
        target = local_target(insn.ops[0].addr)
        if target is not None and target != owner and target not in targets:
            targets.append(target)
    return targets


def reachable(owner, depth):
    seen = set()
    frontier = [owner]
    for _ in range(depth):
        current = []
        for ea in frontier:
            for target in direct_callees(ea):
                if target not in seen and target != owner:
                    seen.add(target)
                    current.append(target)
        frontier = current
    return sorted(seen)


def immediates(function):
    values = set()
    for ea in items(function):
        insn = decode(ea)
        if insn is None:
            continue
        for op in insn.ops:
            if int(op.type) == O_IMM:
                values.add(int(op.value) & 0xFFFFFFFF)
    return values


def shader_creator(candidates):
    return [ea for ea in candidates if {VERTEX_SHADER, FRAGMENT_SHADER} <= immediates(ea)]


# Memory operands this function writes, as (base register, displacement, size).
def member_writes(function):
    writes = []
    for ea in items(function):
        insn = decode(ea)
        if insn is None:
            continue
        for index, op in enumerate(insn.ops):
            if int(op.type) == 0:
                break
            if int(op.type) not in (O_PHRASE, O_DISPL):
                continue
            if not changes_operand(insn, index):
                continue
            displacement = int(op.addr) if int(op.type) == O_DISPL else 0
            size = ida_ua.get_dtype_size(op.dtype)
            writes.append((int(op.reg), displacement, size))
    return writes


# The stack entry slot a register was last loaded from, or None.
def entry_slot(function, register, before_ea):
    for ea in reversed(items(function)):
        if ea >= before_ea:
            continue
        insn = decode(ea)
        if insn is None:
            continue
        if insn.get_canon_mnem() in ("call", "jmp") and register in CALL_CLOBBERED:
            return None
        if int(insn.ops[0].type) != O_REG or int(insn.ops[0].reg) != register or not writes_operand_zero(insn):
            continue
        if insn.get_canon_mnem() != "mov":
            return None
        source = insn.ops[1]
        if int(source.type) not in (O_PHRASE, O_DISPL) or int(source.reg) != REG_ESP:
            return None
        displacement = int(source.addr) if int(source.type) == O_DISPL else 0
        return displacement if displacement >= 0 else None
    return None


def indirect_branches(function):
    sites = []
    for index, ea in enumerate(items(function)):
        insn = decode(ea)
        if insn is None or insn.get_canon_mnem() not in ("call", "jmp"):
            continue
        if int(insn.ops[0].type) in (O_REG, O_MEM, O_PHRASE, O_DISPL):
            sites.append(index)
    return sites


# Classify a shader wrapper: InitShader first, flag guard, one glUseProgram branch.
def classify(function, init_shader):
    listing = items(function)
    if not listing:
        return None
    first_call = None
    for ea in listing:
        insn = decode(ea)
        if insn is None or insn.get_canon_mnem() != "call" or int(insn.ops[0].type) != O_NEAR:
            continue
        target = local_target(insn.ops[0].addr)
        if target is not None:
            first_call = target
            break
    if first_call != init_shader:
        return None

    branches = indirect_branches(function)
    if len(branches) != 1:
        return None
    branch = branches[0]

    for ea in listing:
        insn = decode(ea)
        if insn is None or insn.get_canon_mnem() != "cmp":
            continue
        left, right = insn.ops[0], insn.ops[1]
        if (
            int(left.type) != O_DISPL
            or int(right.type) != O_IMM
            or int(right.value) != 0
            or ida_ua.get_dtype_size(left.dtype) != 1
        ):
            continue
        flag_slot = entry_slot(function, int(left.reg), ea)
        if flag_slot is None:
            continue

        # The argument of the tail glUseProgram call is the last stack store.
        for index in range(branch - 1, -1, -1):
            store = decode(listing[index])
            if store is None:
                continue
            if int(store.ops[0].type) not in (O_PHRASE, O_DISPL) or int(store.ops[0].reg) != REG_ESP:
                continue
            source = store.ops[1]
            if int(source.type) == O_IMM and int(source.value) == 0:
                return {"kind": "disable", "flag": int(left.addr) if int(left.type) == O_DISPL else 0}
            if int(source.type) != O_REG:
                return None
            register = int(source.reg)
            definition = None
            for back in range(index - 1, -1, -1):
                candidate = decode(listing[back])
                if candidate is None:
                    break
                if candidate.get_canon_mnem() in ("call", "jmp") and register in CALL_CLOBBERED:
                    break
                if (
                    int(candidate.ops[0].type) == O_REG
                    and int(candidate.ops[0].reg) == register
                    and writes_operand_zero(candidate)
                ):
                    definition = candidate
                    break
            if definition is None or definition.get_canon_mnem() != "mov":
                return None
            origin = definition.ops[1]
            if int(origin.type) in (O_PHRASE, O_DISPL):
                argument_slot = entry_slot(function, int(origin.reg), listing[index])
                displacement = int(origin.addr) if int(origin.type) == O_DISPL else 0
            elif int(origin.type) == O_REG:
                argument_slot = entry_slot(function, int(origin.reg), listing[index])
                displacement = None
            else:
                return None
            if argument_slot != flag_slot:
                continue
            payload = {"kind": "enable", "flag": int(left.addr) if int(left.type) == O_DISPL else 0}
            if displacement is not None:
                payload["program"] = displacement
            return payload
    return None


def main():
    if func_start(PRED) != PRED:
        return {"error": "DrawPortals predecessor is not a function start"}
    candidates = reachable(PRED, MAX_CALL_DEPTH)
    creators = shader_creator(candidates)
    if len(creators) != 1:
        return {"error": "InitShader candidates: %s" % [hex(ea) for ea in creators]}
    init_shader = creators[0]

    toggles = []
    for ea in candidates:
        if ea == init_shader:
            continue
        classified = classify(ea, init_shader)
        if classified is not None:
            classified["function"] = ea
            toggles.append(classified)
    enable = [item for item in toggles if item["kind"] == "enable"]
    disable = [item for item in toggles if item["kind"] == "disable"]
    if len(enable) > 1 or len(disable) > 1:
        return {"error": "ambiguous shader toggles: %s" % toggles}
    flags = {item["flag"] for item in toggles}
    if len(flags) > 1:
        return {"error": "shader toggles disagree on the flag member: %s" % toggles}
    programs = {item.get("program") for item in enable}
    if len(programs) > 1:
        return {"error": "shader toggles disagree on the program member: %s" % toggles}

    # Every member the wrappers named must be written by InitShader itself.
    writes = member_writes(init_shader)
    if flags:
        flag = next(iter(flags))
        if not any(displacement == flag and size == 1 for _, displacement, size in writes):
            return {"error": "InitShader does not write the shader flag member %#x" % flag}
    if len(programs) == 1 and None not in programs:
        program = next(iter(programs))
        if not any(displacement == program and size == 4 for _, displacement, size in writes):
            return {"error": "InitShader does not write the program member %#x" % program}

    return {
        "init": init_shader,
        "enable": enable[0]["function"] if enable else None,
        "disable": disable[0]["function"] if disable else None,
        "flag": next(iter(flags)) if flags else None,
        "program": next(iter(programs)) if programs else None,
        "candidates": [hex(ea) for ea in candidates],
    }


emit(main())
"""
)


async def _eval(session, code, debug=False):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        if debug:
            print("shader-chain walk stderr: " + structured["stderr"][:4000])
        return ""
    return structured.get("stdout") or ""


async def _function_payload(session, func_name, ea, image_base, skill_name, debug):
    function = await u._inspect_function_via_mcp(session, ea, image_base, func_name)
    across = function is None
    if across:
        function = await u._inspect_function_via_mcp(
            session, ea, image_base, func_name, allow_across_function_boundary=True
        )
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result for {func_name} at {ea:#x}")
        return None
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
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
    _ = old_yaml_map, new_binary_dir, platform
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in TARGETS}
    if not any(outputs.values()):
        if debug:
            print(f"{skill_name}: no requested output among {TARGETS}")
        return False

    predecessor = u._load_yaml_mapping(Path(new_binary_dir) / f"{PREDECESSOR}.{platform}.yaml")
    if not predecessor or predecessor.get("func_name") != PREDECESSOR:
        if debug:
            print(f"{skill_name}: {PREDECESSOR} predecessor is missing or has a foreign identity")
        return False

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@PRED@@", repr(int(predecessor["func_va"], 0)))
        .replace("@@VERTEX_SHADER@@", str(GL_VERTEX_SHADER))
        .replace("@@FRAGMENT_SHADER@@", str(GL_FRAGMENT_SHADER))
        .replace("@@MAX_CALL_DEPTH@@", str(MAX_CALL_DEPTH))
    )
    located = None
    for line in (await _eval(session, code, debug=debug)).splitlines():
        if line.startswith(MARKER):
            located = json.loads(line[len(MARKER) :])
            break
    if not located or located.get("error"):
        if debug:
            print(f"{skill_name}: walk failed: {located}")
        return False

    addresses = {
        INIT_NAME: int(located["init"]),
        ENABLE_NAME: int(located["enable"]) if located.get("enable") is not None else None,
        DISABLE_NAME: int(located["disable"]) if located.get("disable") is not None else None,
    }
    if debug:
        print(f"{skill_name}: " + ", ".join(f"{name}={value:#x}" for name, value in addresses.items() if value))

    # A requested symbol that this build does not carry is a coverage error, not
    # a silent omission: only the config may declare an absent symbol.
    for name, output in outputs.items():
        if output is None:
            continue
        if addresses[name] is None:
            if debug:
                print(f"{skill_name}: {name} was requested but does not exist in this build")
            return False

    payloads = {}
    for name, output in outputs.items():
        if output is None:
            continue
        payload = await _function_payload(session, name, addresses[name], image_base, skill_name, debug)
        if payload is None:
            return False
        payloads[name] = (output, payload)
    for name, (output, payload) in payloads.items():
        u.write_func_yaml(output, payload)
        if debug:
            print(f"{skill_name}: wrote {name} at {payload['func_va']} (size {payload['func_size']})")
    return True
