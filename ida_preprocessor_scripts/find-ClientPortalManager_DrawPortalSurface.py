#!/usr/bin/env python3
"""Locate the Sven Co-op client ClientPortalManager portal-surface draw pair.

``ClientPortalManager::DrawPortals`` is the only owner of the diagnostic
"Invalid GL_ACTIVE_TEXTURE, unable to reset. Portals will not be drawn."
(plural wording; the three sibling portal diagnostics already consumed by this
repository use different sentences). From that predecessor both requested
symbols are recovered with a deterministic instruction walk, so no byte
signature and no LLM step participates in discovery:

``ClientPortalManager::DrawPortalSurface`` ends with the overlay decision

    texinfo = GetOriginalSurfaceTexture(surf);
    if (texinfo && texinfo->texture && texinfo->texture->name[0] == '{')
        DrawOverlay(portal, surf, texinfo->texture->gl_texturenum);

which compiles on every validated build to

    call  <GetOriginalSurfaceTexture>
    ...                                  ; test/jcc only
    mov   R, [eax+24h]                   ; mtexinfo_t::texture
    ...                                  ; test/jcc only
    cmp   byte ptr [R], 7Bh              ; texture_t::name[0] == '{'

Exactly one direct callee of the predecessor carries that sequence, and the
direct call feeding it is ``GetOriginalSurfaceTexture``. The weaker rule "any
``cmp byte ptr [reg], 7Bh``" is not sufficient: ``ClientPortal::IsSurfaceVisible``
is also a direct predecessor callee and compares the same character, but reads
its texinfo from the surface instead of a call result.

svencoop-8948 client.so keeps its symbol table and confirms the naming and the
walk (``_ZN19ClientPortalManager17DrawPortalSurfaceER12ClientPortalP10msurface_sj``
and ``_ZN19ClientPortalManager25GetOriginalSurfaceTextureEP10msurface_s``); on
that build every call goes through a PLT stub, so the walk resolves stubs to
their local definitions. svencoop-10257 client.so references the anchor literal
only through a GOTOFF displacement, which the shared SvEngine PIC owner
fallback resolves.
"""

import json

import ida_analyze_util as u
from ida_elf import ELF_RESOLVER_PY
from ida_preprocessor_scripts._sven_client_pic_common import unique_string_owner_ea

DRAW_NAME = "ClientPortalManager_DrawPortalSurface"
TEXTURE_NAME = "ClientPortalManager_GetOriginalSurfaceTexture"
TARGETS = (DRAW_NAME, TEXTURE_NAME)

LITERAL = "Invalid GL_ACTIVE_TEXTURE, unable to reset. Portals will not be drawn.\n"
MARKER = "__I160_PORTALSURFACE__"

# mtexinfo_t::texture and the GoldSrc transparent-texture name prefix '{'.
TEXINFO_TEXTURE_OFFSET = 0x24
TRANSPARENT_NAME_BYTE = 0x7B
# call / test / jcc / mov / test / jcc is six instructions on the validated
# builds; keep a small margin without letting the window leave the idiom.
MAX_LOOKBACK = 8

WALK = (
    ELF_RESOLVER_PY
    + r"""
import ida_funcs, ida_segment, ida_ua, idautils, idc, json

MARKER = @@MARKER@@
PRED = @@PRED@@
TEXTURE_OFFSET = @@TEXTURE_OFFSET@@
NAME_BYTE = @@NAME_BYTE@@
MAX_LOOKBACK = @@MAX_LOOKBACK@@

O_REG, O_PHRASE, O_DISPL, O_IMM, O_NEAR = 1, 3, 4, 5, 7
REG_EAX = 0


def emit(payload):
    print(MARKER + json.dumps(payload))


def func_start(ea):
    function = ida_funcs.get_func(ea)
    return int(function.start_ea) if function else None


# Resolve a call target to a local function start, never a PLT stub.
def local_target(ea):
    target = resolve_elf_plt(int(ea))
    segment = ida_segment.getseg(target)
    if segment is None or ida_segment.get_segm_name(segment).startswith(".plt"):
        return None
    return target if func_start(target) == target else None


def direct_callees(owner):
    targets = set()
    for pc in idautils.FuncItems(owner):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        if idc.get_operand_type(pc, 0) != O_NEAR:
            continue
        target = local_target(idc.get_operand_value(pc, 0))
        if target is not None and target != owner:
            targets.add(target)
    return sorted(targets)


# call -> mov R,[eax+TEXTURE_OFFSET] -> cmp byte ptr [R], NAME_BYTE
def overlay_sites(owner):
    items = list(idautils.FuncItems(owner))
    sites = []
    for position, ea in enumerate(items):
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            continue
        if (idc.print_insn_mnem(ea) or "").lower() != "cmp":
            continue
        if int(insn.ops[0].type) != O_PHRASE:
            continue
        if int(insn.ops[1].type) != O_IMM or int(insn.ops[1].value) != NAME_BYTE:
            continue
        tracked = int(insn.ops[0].reg)
        loaded = False
        for index in range(position - 1, max(position - 1 - MAX_LOOKBACK, -1), -1):
            back = items[index]
            decoded = ida_ua.insn_t()
            if not ida_ua.decode_insn(decoded, back):
                break
            mnemonic = (idc.print_insn_mnem(back) or "").lower()
            if mnemonic == "mov" and int(decoded.ops[0].type) == O_REG and int(decoded.ops[0].reg) == tracked:
                if (
                    not loaded
                    and int(decoded.ops[1].type) == O_DISPL
                    and int(decoded.ops[1].reg) == REG_EAX
                    and int(decoded.ops[1].addr) == TEXTURE_OFFSET
                ):
                    tracked = REG_EAX
                    loaded = True
                    continue
                break
            if mnemonic == "call":
                if not loaded or int(decoded.ops[0].type) != O_NEAR:
                    break
                target = local_target(decoded.ops[0].addr)
                if target is not None and target != owner:
                    sites.append({"cmp": hex(int(ea)), "call": hex(int(back)), "callee": hex(target)})
                break
    return sites


res = {}
if func_start(PRED) != PRED:
    res["error"] = "predecessor is not a function start"
    emit(res)
else:
    candidates = []
    for callee in direct_callees(PRED):
        sites = overlay_sites(callee)
        if sites:
            candidates.append({"func": hex(callee), "sites": sites})
    res["candidates"] = candidates
    if len(candidates) != 1:
        res["error"] = "portal-surface overlay candidate is not unique"
    elif len(candidates[0]["sites"]) != 1:
        res["error"] = "portal-surface overlay site is not unique"
    else:
        site = candidates[0]["sites"][0]
        draw = int(candidates[0]["func"], 16)
        texture = int(site["callee"], 16)
        if draw == texture:
            res["error"] = "overlay call target equals its own function"
        else:
            res["draw"] = {"va": hex(draw), "call_site": site["call"], "cmp_site": site["cmp"]}
            res["texture"] = {"va": hex(texture)}
    emit(res)
"""
)


async def _eval(session, code, debug=False):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        if debug:
            print("portal-surface walk stderr: " + structured["stderr"][:4000])
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
    if not all(outputs.values()):
        if debug:
            print(f"{skill_name}: expected outputs missing for {TARGETS}")
        return False

    predecessor = await unique_string_owner_ea(session, LITERAL, label=skill_name, debug=debug)
    if predecessor is None:
        if debug:
            print(f"{skill_name}: no unique owner for the portal-draw diagnostic")
        return False

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@PRED@@", repr(int(predecessor)))
        .replace("@@TEXTURE_OFFSET@@", str(TEXINFO_TEXTURE_OFFSET))
        .replace("@@NAME_BYTE@@", str(TRANSPARENT_NAME_BYTE))
        .replace("@@MAX_LOOKBACK@@", str(MAX_LOOKBACK))
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
        DRAW_NAME: int(located["draw"]["va"], 0),
        TEXTURE_NAME: int(located["texture"]["va"], 0),
    }
    if debug:
        print(f"{skill_name}: predecessor {predecessor:#x}, " + ", ".join(f"{k}={v:#x}" for k, v in addresses.items()))

    # Both payloads are validated before either artifact is written so a
    # half-emitted pair can never reach bin_artifacts.
    payloads = {}
    for name in TARGETS:
        payload = await _function_payload(session, name, addresses[name], image_base, skill_name, debug)
        if payload is None:
            return False
        payloads[name] = payload
    for name in TARGETS:
        u.write_func_yaml(outputs[name], payloads[name])
    return True
