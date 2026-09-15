#!/usr/bin/env python3
"""Locate the R_DrawParticles helper calls from the particle renderer body.

engine/r_part.c R_DrawParticles closes with the particle passes
``R_TracerDraw(); R_BeamDrawList();`` and frees dead particle lists through
R_FreeDeadParticles, which the tracer pass also calls. Discovery walks the
current R_DrawParticles artifact body only:

* R_BeamDrawList is the mid-size function called exclusively by the renderer
  whose own callees include the beam-draw pair (R_BeamDraw / R_DrawBeamEntList).
* R_TracerDraw is the large remaining pass with the renderer as its only
  caller. GCC builds (GoldSrc Linux) may inline it into the renderer; the
  symbol is then absent and the requesting platform must not expect it.
* R_FreeDeadParticles is the unique small no-callee helper that is either
  called by both the renderer and the tracer pass, or called repeatedly
  inside the renderer body itself on builds where the tracer pass is inlined.

No byte signature participates in discovery."""

import json
from pathlib import Path

import ida_analyze_util as u

TARGETS = ("R_FreeDeadParticles", "R_TracerDraw", "R_BeamDrawList")
RDP = "R_DrawParticles"
MARKER = "__R124_PARTICLE_CALLS__"
MIN_BODY = 60
THUNK_MAX = 16
BEAM_MIN = 250
BEAM_MAX = 900
TRACER_MIN = 900
FREE_MAX = 400

WALK = r"""
import idautils, ida_funcs, idc, json

BEAM_MIN = @@BEAM_MIN@@
BEAM_MAX = @@BEAM_MAX@@
TRACER_MIN = @@TRACER_MIN@@
FREE_MAX = @@FREE_MAX@@

MARKER = @@MARKER@@
RDP = @@RDP@@
MIN_BODY = @@MIN_BODY@@
THUNK_MAX = @@THUNK_MAX@@

def emit(d):
    print(MARKER + json.dumps(d))

def fn(ea):
    f = ida_funcs.get_func(ea)
    return int(f.start_ea) if f else None

def fsize(ea):
    f = ida_funcs.get_func(ea)
    return int(f.end_ea - f.start_ea) if f else 0

def internal_calls(o):
    out = []
    for pc in idautils.FuncItems(o):
        if (idc.print_insn_mnem(pc) or "").lower() != "call":
            continue
        t = idc.get_operand_value(pc, 0)
        tf = fn(t) if t else None
        if tf is None or tf != t or fsize(tf) <= THUNK_MAX:
            continue
        out.append((int(pc), int(tf)))
    return out

def callees(o):
    return {t for _, t in internal_calls(o)}

def callers(o):
    return {fn(x) for x in idautils.CodeRefsTo(o, False) if fn(x)}

res = {}
seq = internal_calls(RDP)
if len(seq) < 3:
    res["error"] = "R_DrawParticles has too few internal calls"
    emit(res)
else:
    rdp_callees = sorted(callees(RDP))
    # R_BeamDrawList: mid-size function called only by the particle renderer
    # whose own callees include the beam-draw pair (R_BeamDraw / R_DrawBeamEntList).
    beams = [c for c in rdp_callees
             if BEAM_MIN <= fsize(c) <= BEAM_MAX
             and callers(c) == {RDP}
             and any(fsize(s) >= BEAM_MIN for s in callees(c))]
    # R_TracerDraw: the large remaining particle pass called only by the renderer.
    tracers = [c for c in rdp_callees
               if fsize(c) >= TRACER_MIN and callers(c) == {RDP} and c not in beams]
    res["beam_candidates"] = [(hex(c), fsize(c)) for c in beams]
    res["tracer_candidates"] = [(hex(c), fsize(c)) for c in tracers]
    if len(beams) != 1 or len(tracers) > 1:
        res["error"] = "particle pass candidates are not unique"
        emit(res)
    else:
        beam = beams[0]
        res["R_BeamDrawList"] = {"va": hex(beam), "size": fsize(beam),
                                 "callers": [hex(x) for x in sorted(callers(beam))]}
        if not tracers:
            # GCC builds inline R_TracerDraw into the particle renderer body;
            # the symbol is simply absent on those targets.
            res["R_TracerDraw"] = None
            res["tracer_inlined"] = True
            tracer = None
        else:
            tracer = tracers[0]
            res["R_TracerDraw"] = {"va": hex(tracer), "size": fsize(tracer),
                                   "callers": [hex(x) for x in sorted(callers(tracer))]}
        free_cands = set()
        if tracer is not None:
            free_cands.update(callees(RDP) & callees(tracer))
        counts = {}
        for _, t in seq:
            counts[t] = counts.get(t, 0) + 1
        for t, n in counts.items():
            if n >= 2:
                free_cands.add(t)
        free_cands -= {RDP, beam, tracer}
        free_cands = [c for c in sorted(free_cands)
                      if MIN_BODY <= fsize(c) <= FREE_MAX
                      and len(callees(c)) <= 1
                      and 2 <= len(callers(c)) <= 10
                      and (tracer is None or RDP in callers(c))]
        if tracer is None:
            # With the tracer pass inlined, the renderer itself calls
            # R_FreeDeadParticles for its own and the tracer's list, so the
            # shared small helpers called only twice (for example the cull
            # test) drop out.
            free_cands = [c for c in free_cands if counts.get(c, 0) >= 3]
        res["free_candidates"] = [(hex(c), fsize(c), counts.get(c, 0)) for c in free_cands]
        if len(free_cands) != 1:
            res["error"] = "R_FreeDeadParticles candidate is not unique"
        else:
            res["R_FreeDeadParticles"] = {
                "va": hex(free_cands[0]),
                "size": fsize(free_cands[0]),
                "callers": [hex(x) for x in sorted(callers(free_cands[0]))],
            }
        emit(res)
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("particle-calls walk stderr: " + structured["stderr"][:4000])
        return ""
    return structured.get("stdout") or ""


async def _write_target(session, outputs, symbol, info, image_base, debug, skill_name):
    if outputs.get(symbol) is None or not info:
        return False
    function = await u._inspect_function_via_mcp(session, int(info["va"], 0), image_base, symbol)
    if not function:
        function = await u._inspect_function_via_mcp(
            session,
            int(info["va"], 0),
            image_base,
            symbol,
            allow_across_function_boundary=True,
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result for {symbol}")
        return False
    payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(outputs[symbol], payload)
    return True


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
    new_binary_dir = Path(new_binary_dir)
    outputs = {name: u._output_for_symbol(expected_outputs, name) for name in TARGETS}
    if not any(outputs.values()):
        return False

    rdp_data = u._load_yaml_mapping(new_binary_dir / f"{RDP}.{platform}.yaml")
    if not rdp_data or rdp_data.get("func_va") is None:
        if debug:
            print(f"{skill_name}: missing {RDP} artifact")
        return False
    rdp_va = u._parse_int(rdp_data["func_va"], "func_va")

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@RDP@@", repr(rdp_va))
        .replace("@@MIN_BODY@@", str(MIN_BODY))
        .replace("@@THUNK_MAX@@", str(THUNK_MAX))
        .replace("@@BEAM_MIN@@", str(BEAM_MIN))
        .replace("@@BEAM_MAX@@", str(BEAM_MAX))
        .replace("@@TRACER_MIN@@", str(TRACER_MIN))
        .replace("@@FREE_MAX@@", str(FREE_MAX))
    )
    stdout = await _eval(session, code)
    located = None
    for line in stdout.splitlines():
        if line.startswith(MARKER):
            located = json.loads(line[len(MARKER) :])
            break
    if not located or "error" in located:
        if debug:
            print(f"{skill_name}: walk failed: {located}")
        return False

    written = 0
    for symbol in TARGETS:
        if outputs[symbol] is None:
            continue
        if await _write_target(session, outputs, symbol, located.get(symbol), image_base, debug, skill_name):
            written += 1
    return written == sum(1 for name in TARGETS if outputs[name])
