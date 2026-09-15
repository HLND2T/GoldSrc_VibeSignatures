#!/usr/bin/env python3
"""Locate R_ResetLatched and its CL_LinkPacketEntities call sites.

engine/cl_ents.c CL_LinkPacketEntities owns the unique diagnostic literal
``Tried to link edict %i without model`` and calls R_ResetLatched twice
(full reset then EF_NOINTERP reset), while no other doubly-called helper in
that body matches the latched-state reset role: candidates must stay within
the size window of the reset body, be called from at least one further
entity-linking function (CL_ResetLatchedState / CL_LinkPlayers), and remain
unique. Every direct CL_LinkPacketEntities -> R_ResetLatched call site is
emitted as a numbered patch artifact through the shared func-to-func callsite
helper. No byte signature participates in discovery.
"""

import json
import re
from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts._func_to_func_callsites_common import locate_callsites

TARGET = "R_ResetLatched"
CALLSITE_PREFIX = "CL_LinkPacketEntities_to_R_ResetLatched_callsite_"
DIAGNOSTIC = "Tried to link edict %i without model\n"
MARKER = "__R124_RESETLATCHED__"
MIN_SIZE = 100
MAX_SIZE = 1200
MIN_EXTRA_CALLERS = 1
MAX_EXTRA_CALLERS = 4

WALK = r"""
import idautils, ida_funcs, idc, ida_segment, ida_bytes, json

MARKER = @@MARKER@@
NEEDLE = @@NEEDLE@@
MIN_SIZE = @@MIN_SIZE@@
MAX_SIZE = @@MAX_SIZE@@
MIN_EXTRA = @@MIN_EXTRA@@
MAX_EXTRA = @@MAX_EXTRA@@

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
        if tf is None or tf != t or fsize(tf) <= 16:
            continue
        out.append((int(pc), int(tf)))
    return out

def callers(o):
    return sorted({fn(x) for x in idautils.CodeRefsTo(o, False) if fn(x)})

def find_cstr(s):
    hits = []
    for si in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(si)
        if not seg:
            continue
        nm = ida_segment.get_segm_name(seg) or ""
        if not nm or nm.startswith(".text") or nm.startswith(".plt"):
            continue
        data = ida_bytes.get_bytes(int(seg.start_ea), int(seg.end_ea) - int(seg.start_ea))
        if not data:
            continue
        i = data.find(s)
        while i != -1:
            hits.append(int(seg.start_ea) + i)
            i = data.find(s, i + 1)
    return hits

res = {}
owners = set()
for ea in find_cstr(NEEDLE):
    for x in idautils.DataRefsTo(ea):
        f = fn(x)
        if f is not None:
            owners.add(f)
res["owners"] = [hex(o) for o in sorted(owners)]
if len(owners) != 1:
    res["error"] = "diagnostic literal owner is not unique"
    emit(res)
else:
    owner = next(iter(owners))
    res["CL_LinkPacketEntities"] = hex(owner)
    counts = {}
    for _, t in internal_calls(owner):
        counts[t] = counts.get(t, 0) + 1
    cands = []
    for t, n in sorted(counts.items()):
        if n < 2:
            continue
        if not (MIN_SIZE <= fsize(t) <= MAX_SIZE):
            continue
        cl = callers(t)
        if owner not in cl or not (MIN_EXTRA <= len(cl) - 1 <= MAX_EXTRA):
            continue
        cands.append({"va": hex(t), "size": fsize(t), "calls": n,
                      "callers": [hex(c) for c in cl]})
    res["candidates"] = cands
    # R_ResetLatched's callers are exactly the cl_ents link helpers, so the
    # doubly-called candidate with the fewest extra callers wins; ties fail.
    best = min((len(c["callers"]) for c in cands), default=None)
    cands = [c for c in cands if len(c["callers"]) == best]
    if len(cands) != 1:
        res["error"] = "R_ResetLatched candidate is not unique"
    else:
        res["R_ResetLatched"] = cands[0]
    emit(res)
"""


async def _eval(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    structured = raw.get("structured_content") or {}
    if structured.get("stderr"):
        print("resetlatched walk stderr: " + structured["stderr"][:4000])
        return ""
    return structured.get("stdout") or ""


def _expected_callsite_indexes(expected_outputs):
    indexes = []
    for entry in expected_outputs:
        stem = Path(entry).name
        for suffix in (".windows.yaml", ".linux.yaml", ".yaml"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        match = re.fullmatch(rf"{re.escape(CALLSITE_PREFIX)}(\d+)", stem)
        if match:
            indexes.append((int(match.group(1)), entry))
    indexes.sort()
    return indexes


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
    func_output = u._output_for_symbol(expected_outputs, TARGET)
    callsites = _expected_callsite_indexes(expected_outputs)
    if func_output is None or not callsites:
        if debug:
            print(f"{skill_name}: expected outputs missing function or callsites")
        return False
    if [index for index, _ in callsites] != list(range(len(callsites))):
        if debug:
            print(f"{skill_name}: callsite indexes are not contiguous")
        return False

    code = (
        WALK.replace("@@MARKER@@", repr(MARKER))
        .replace("@@NEEDLE@@", repr(DIAGNOSTIC.encode("latin-1") + b"\x00"))
        .replace("@@MIN_SIZE@@", str(MIN_SIZE))
        .replace("@@MAX_SIZE@@", str(MAX_SIZE))
        .replace("@@MIN_EXTRA@@", str(MIN_EXTRA_CALLERS))
        .replace("@@MAX_EXTRA@@", str(MAX_EXTRA_CALLERS))
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

    info = located["R_ResetLatched"]
    rl_ea = int(info["va"], 0)
    owner_ea = int(located["CL_LinkPacketEntities"], 0)
    function = await u._inspect_function_via_mcp(session, rl_ea, image_base, TARGET)
    if not function:
        function = await u._inspect_function_via_mcp(
            session, rl_ea, image_base, TARGET, allow_across_function_boundary=True
        )
        if function:
            function["func_sig_allow_across_function_boundary"] = True
    if not function:
        if debug:
            print(f"{skill_name}: no inspect result for {TARGET}")
        return False
    payload = {k: function[k] for k in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if function.get("func_sig_allow_across_function_boundary"):
        payload["func_sig_allow_across_function_boundary"] = True
    u.write_func_yaml(func_output, payload)

    located_sites = await locate_callsites(session, owner_ea, rl_ea)
    if located_sites is None or located_sites.get("error") or located_sites.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: callsite locator failed {located_sites}")
        return False
    sites = located_sites.get("sites")
    if not isinstance(sites, list) or len(sites) != len(callsites):
        if debug:
            print(
                f"{skill_name}: found {len(sites) if isinstance(sites, list) else 0} callsites, expected {len(callsites)}"
            )
        return False
    for (index, output), site in zip(callsites, sites):
        if not isinstance(site, dict):
            return False
        try:
            patch_ea = int(site["ea"], 0)
            patch_sig_disp = int(site["patch_sig_disp"])
            insn_len = int(site["insn_len"])
        except (TypeError, ValueError, KeyError):
            return False
        patch_sig = site.get("patch_sig")
        if not isinstance(patch_sig, str) or not patch_sig.strip():
            return False
        if patch_ea < owner_ea or patch_sig_disp != 0 or insn_len <= 0:
            return False
        unique_ea = await u._find_unique_bytes(session, patch_sig)
        if unique_ea != patch_ea:
            if debug:
                print(f"{skill_name}: callsite {index} signature is not unique")
            return False
        u.write_patch_yaml(
            output,
            {
                "patch_name": f"{CALLSITE_PREFIX}{index}",
                "patch_va": hex(patch_ea),
                "patch_rva": hex(patch_ea - int(image_base)),
                "patch_sig": patch_sig,
                "patch_sig_disp": patch_sig_disp,
            },
        )
    return True
