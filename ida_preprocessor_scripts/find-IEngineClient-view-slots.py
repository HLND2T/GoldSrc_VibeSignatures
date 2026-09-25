#!/usr/bin/env python3
"""Locate the IEngineClient::PushView / PopView virtual slots from the Sven client.

``ClientPortalManager::DrawPortals`` ends with ``g_pEngineClient->PopView()`` and
``ClientPortalManager::RenderPortals`` calls ``PushView`` once, renders every
portal through ``RenderView`` and restores the view with a final ``PopView``.
Both callers are already covered on every validated Sven client, so the two
engine slots are recovered from those bodies instead of from the engine module,
where no literal or symbol anchors the implementation class.

The walk only accepts real C++ virtual calls: ``call [V+disp]`` where V was
defined by ``mov V, [O]`` with a zero displacement and O is not ``esp``. That
excludes the ``gEngfuncs`` function tables (their slots are loaded through a
non-zero displacement) and the GCC PIC GOT-relative indirect calls, so the
remaining sites are exactly the ``g_pEngineClient`` dispatches of the source:

* DrawPortals carries a single such call, the trailing ``PopView()``.
* RenderPortals carries exactly three, at ``PushView``, ``RenderView`` and
  ``PopView``. They must occupy three consecutive 4-byte slots with the middle
  one equal to DrawPortals' PopView offset, which both orders the triple and
  pins the interface the slots belong to.

``PushView`` and ``PopView`` are emitted as slot-only ``vfunc`` artifacts, so
the delivered offset is absolute for the matched binary and no cross-build
index is reused: the interface grew two slots between the 001 and 002 revisions,
and MSVC emits one deleting-destructor slot less than the Itanium ABI does.
Independently checked against the engine's own ``CEngineClient`` vtable on
svencoop-8948 Windows/Linux and svencoop-10257 Windows/Linux, plus the retained
ELF symbol table of svencoop-8948 hw.so.
"""

import json
from pathlib import Path

import ida_analyze_util as u
from ida_elf import ELF_RESOLVER_PY

PUSH_NAME = "IEngineClient_PushView"
POP_NAME = "IEngineClient_PopView"
TARGETS = (PUSH_NAME, POP_NAME)
RENDER_NAME = "ClientPortalManager_RenderPortals"
DRAW_NAME = "ClientPortalManager_DrawPortals"
VTABLE_NAME = "IEngineClient"
SLOT_WIDTH = 4
# The delivered artifact identity is the source-qualified interface method.
IDENTITIES = {PUSH_NAME: "IEngineClient::PushView", POP_NAME: "IEngineClient::PopView"}

MARKER = "__I245_VIEWSLOTS__"

WALK = (
    ELF_RESOLVER_PY
    + r"""
import ida_funcs, ida_ua, idautils, json

MARKER = @@MARKER@@
RENDER = @@RENDER@@
DRAW = @@DRAW@@
SLOT_WIDTH = @@SLOT_WIDTH@@

O_REG, O_MEM, O_PHRASE, O_DISPL, O_IMM, O_NEAR = 1, 2, 3, 4, 5, 7
REG_ESP = 4
LOOKBACK = 16


def emit(payload):
    print(MARKER + json.dumps(payload))


def decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None


def func_start(ea):
    function = ida_funcs.get_func(ea)
    return int(function.start_ea) if function else None


# call [V+disp] where V was last defined by mov V, [reg] with a zero displacement.
def cpp_vcalls(owner):
    if func_start(owner) != owner:
        return None
    listing = list(idautils.FuncItems(owner))
    sites = []
    for index, ea in enumerate(listing):
        insn = decode(ea)
        if insn is None or insn.get_canon_mnem() != "call" or int(insn.ops[0].type) != O_DISPL:
            continue
        register = int(insn.ops[0].reg)
        offset = int(insn.ops[0].addr) & 0xFFFFFFFF
        for back in range(index - 1, max(index - 1 - LOOKBACK, -1), -1):
            definition = decode(listing[back])
            if definition is None:
                break
            if int(definition.ops[0].type) == O_REG and int(definition.ops[0].reg) == register:
                source = definition.ops[1]
                zero_displacement = int(source.type) == O_PHRASE or (
                    int(source.type) == O_DISPL and (int(source.addr) & 0xFFFFFFFF) == 0
                )
                if (
                    definition.get_canon_mnem() == "mov"
                    and zero_displacement
                    and int(source.reg) != REG_ESP
                ):
                    sites.append({"ea": int(ea), "offset": offset})
                break
            if definition.get_canon_mnem() == "call":
                break
    return sites


def main():
    render = cpp_vcalls(RENDER)
    draw = cpp_vcalls(DRAW)
    if render is None or draw is None:
        return {"error": "portal predecessors are not function starts"}
    if len(draw) != 1:
        return {"error": "DrawPortals engine dispatches: %s" % [hex(s["ea"]) for s in draw]}
    pop = draw[0]["offset"]
    offsets = sorted(site["offset"] for site in render)
    if len(render) != 3 or offsets != [pop - SLOT_WIDTH, pop, pop + SLOT_WIDTH]:
        return {"error": "RenderPortals engine dispatches: %s (PopView %#x)" % (offsets, pop)}
    return {
        "push": pop - SLOT_WIDTH,
        "pop": pop,
        "render_view": pop + SLOT_WIDTH,
        "sites": {hex(site["offset"]): hex(site["ea"]) for site in render},
    }


emit(main())
"""
)


async def _eval(session, code, debug=False):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        if debug:
            print("view-slots walk stderr: " + structured["stderr"][:4000])
        return ""
    return structured.get("stdout") or ""


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
    _ = old_yaml_map, image_base
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in TARGETS}
    if not all(outputs.values()):
        if debug:
            print(f"{skill_name}: expected outputs missing for {TARGETS}")
        return False

    sources = {}
    for stem in (RENDER_NAME, DRAW_NAME):
        artifact = u._load_yaml_mapping(Path(new_binary_dir) / f"{stem}.{platform}.yaml")
        if not artifact or artifact.get("func_name") != stem:
            if debug:
                print(f"{skill_name}: {stem} predecessor is missing or has a foreign identity")
            return False
        sources[stem] = int(artifact["func_va"], 0)

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@RENDER@@", repr(sources[RENDER_NAME]))
        .replace("@@DRAW@@", repr(sources[DRAW_NAME]))
        .replace("@@SLOT_WIDTH@@", str(SLOT_WIDTH))
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

    slots = {PUSH_NAME: int(located["push"]), POP_NAME: int(located["pop"])}
    for name, output in outputs.items():
        offset = slots[name]
        if offset % SLOT_WIDTH or offset < 0:
            if debug:
                print(f"{skill_name}: {name} slot {offset:#x} is not a 4-byte interface slot")
            return False
    payload = {}
    for name, output in outputs.items():
        payload[name] = (
            output,
            {
                "func_name": IDENTITIES[name],
                "vtable_name": VTABLE_NAME,
                "vfunc_offset": hex(slots[name]),
                "vfunc_index": slots[name] // SLOT_WIDTH,
            },
        )
    for name, (output, artifact) in payload.items():
        u.write_func_yaml(output, artifact)
        if debug:
            print(
                f"{skill_name}: wrote {name} slot {artifact['vfunc_offset']} "
                f"({artifact['vfunc_index']}), sites {located['sites']}"
            )
    return True
