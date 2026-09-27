#!/usr/bin/env python3
"""Locate the Sven client portal view-vector AngleVectors call.

MetaHookSv's R_SCClientRedirectRenderPortalAngleVectors redirects the branch
that forwards a portal's own ref_params_t view vectors to the client's
AngleVectors and marks it "pRealCall is the callsite we want." The source
statement is AngleVectors(p->viewangles, p->forward, p->right, p->up) where p
is a ref_params_t; its three output vectors sit at +0x18, +0x24 and +0x30, the
ref_params_t forward/right/up ABI, so the argument setup is a source-level
invariant rather than a build identity.

The host function is ClientPortalManager::RenderPortals, consumed from its
existing string-anchored artifact. The search set is the host body plus the
host's direct rel32 call targets with ELF PLT stubs resolved, because the
statement is inlined into RenderPortals on Windows but outlined by GCC:

* svencoop-10257 client.so: outlined into sub_F78A2, a direct host callee;
* svencoop-8948 client.so: PortalSource::SetupRendering, reached through the
  .plt stub of a direct host call.

Exactly one candidate must survive in the whole search set, and its resolved
callee must also be one of the host's own direct callees, so the site is pinned
to the portal view-vector helper rather than to any other ref_params_t consumer.
Zero or several candidates fails closed. Discovery never uses the MetaHookSv
first-match byte pattern, a window of fixed size, a fixed address, or an old
artifact signature.

The callee is named AngleVectors after the real ELF symbol Sven publishes for
it (svencoop-8948 client.so _Z12AngleVectorsRK6VectorPS_S2_S2_); the 10257
database spells the same function View_AngleVectors, which is a restored local
name, not a published symbol.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_patch_yaml,
)
from ida_elf import ELF_RESOLVER_PY
from ida_preprocessor_scripts._patch_signature_common import run_signature

PATCH_NAME = "ClientPortalManager_RenderPortals_to_AngleVectors_callsite_0"
OWNER_FUNC_NAME = "ClientPortalManager_RenderPortals"
MAX_SEARCH_FUNCS = 96
MAX_LOOKBACK = 12
VIEWANGLES_FORWARD_DISP = 0x18
VIEWANGLES_RIGHT_DISP = 0x24
VIEWANGLES_UP_DISP = 0x30

LOCATE_PY = (
    ELF_RESOLVER_PY
    + r"""
import ida_bytes
import ida_funcs
import idautils
import idc
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER
MAX_SEARCH_FUNCS = MAX_SEARCH_FUNCS_PLACEHOLDER
MAX_LOOKBACK = MAX_LOOKBACK_PLACEHOLDER
REQUIRED_DISPS = {FORWARD_DISP_PLACEHOLDER, RIGHT_DISP_PLACEHOLDER, UP_DISP_PLACEHOLDER}
SCANNABLE_MNEMONICS = ('lea', 'push', 'mov', 'nop')


def insn_mnem(ea):
    return (idc.print_insn_mnem(int(ea)) or '').lower()


def rel32_target(ea):
    raw = ida_bytes.get_bytes(int(ea), 5) or b''
    if len(raw) < 5 or raw[0] not in (0xE8, 0xE9):
        return None
    return int(ea) + 5 + int.from_bytes(raw[1:5], 'little', signed=True)


def lea_operand(disasm):
    text = (disasm or '').strip()
    if not text.lower().startswith('lea '):
        return None
    try:
        _dest, right = text[4:].split(',', 1)
    except ValueError:
        return None
    right = right.split(';')[0].strip()
    if not (right.startswith('[') and right.endswith(']')):
        return None
    inner = right[1:-1]
    if '+' not in inner:
        return None
    base, displacement = inner.rsplit('+', 1)
    displacement = displacement.strip().lower()
    try:
        if displacement.startswith('0x'):
            value = int(displacement, 16)
        elif displacement.endswith('h'):
            value = int(displacement[:-1], 16)
        else:
            return None
    except ValueError:
        return None
    return base.strip(), value


def func_desc(ea):
    function = ida_funcs.get_func(int(ea))
    if function is None:
        return None
    return {
        'start': int(function.start_ea),
        'end': int(function.end_ea),
        'name': idc.get_func_name(int(function.start_ea)) or '',
    }


def body(start):
    return [int(ea) for ea in idautils.FuncItems(int(start))]


def refparams_vector_register(items, index):
    # Base register of the lea r,[r+0x18]/[r+0x24]/[r+0x30] argument triple.
    seen = {}
    for back in range(1, int(MAX_LOOKBACK) + 1):
        if index - back < 0:
            break
        previous = items[index - back]
        mnemonic = insn_mnem(previous)
        if mnemonic not in SCANNABLE_MNEMONICS:
            break
        if mnemonic != 'lea':
            continue
        parsed = lea_operand(idc.generate_disasm_line(previous, 0))
        if parsed is None:
            continue
        base, value = parsed
        seen.setdefault(base, set()).add(value)
    return sorted(base for base, values in seen.items() if REQUIRED_DISPS <= values)


globals().update(locals())

try:
    owner = func_desc(OWNER_EA)
    if owner is None or owner['start'] != int(OWNER_EA):
        raise RuntimeError('owner is not a function start')

    search_starts = [owner['start']]
    owner_callees = set()
    for ea in body(owner['start']):
        if insn_mnem(ea) != 'call':
            continue
        target = rel32_target(ea)
        if target is None:
            continue
        resolved = resolve_elf_plt(target)
        function = ida_funcs.get_func(resolved)
        if function is None or int(function.start_ea) != resolved:
            continue
        owner_callees.add(resolved)
        if resolved not in search_starts:
            search_starts.append(resolved)
        if len(search_starts) >= int(MAX_SEARCH_FUNCS):
            break

    candidates = []
    for start in search_starts:
        items = body(start)
        for index, ea in enumerate(items):
            if insn_mnem(ea) != 'call':
                continue
            bases = refparams_vector_register(items, index)
            if not bases:
                continue
            target = rel32_target(ea)
            resolved = resolve_elf_plt(target) if target is not None else None
            # The host calls the portal view-vector helper itself, so the same
            # resolved callee must also be one of the host's direct callees.
            if resolved not in owner_callees:
                continue
            window = max(0, index - int(MAX_LOOKBACK))
            candidates.append({
                'ea': int(ea),
                'enclosing': func_desc(start),
                'disasm': idc.generate_disasm_line(int(ea), 0) or '',
                'base_registers': bases,
                'target': target,
                'target_desc': func_desc(resolved),
                'window': [idc.generate_disasm_line(item, 0) or '' for item in items[window:index + 1]],
            })

    result = json.dumps({
        'pointer_size': 4,
        'owner': owner,
        'search_set_size': len(search_starts),
        'candidates': candidates,
    })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""
)


def _function_artifact_path(new_binary_dir, platform, func_name):
    return Path(new_binary_dir) / f"{func_name}.{platform}.yaml"


def _function_artifact(new_binary_dir, platform, func_name, image_base):
    artifact = _load_yaml_mapping(_function_artifact_path(new_binary_dir, platform, func_name))
    if not artifact or artifact.get("func_name") != func_name:
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    if func_ea < int(image_base):
        return None
    return artifact, func_ea


def _function_allows_across_boundary(artifact):
    return bool(artifact.get("func_sig_allow_across_function_boundary"))


async def _locate_candidates(session, owner_ea):
    code = (
        LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", str(int(owner_ea)))
        .replace("MAX_SEARCH_FUNCS_PLACEHOLDER", str(MAX_SEARCH_FUNCS))
        .replace("MAX_LOOKBACK_PLACEHOLDER", str(MAX_LOOKBACK))
        .replace("FORWARD_DISP_PLACEHOLDER", str(VIEWANGLES_FORWARD_DISP))
        .replace("RIGHT_DISP_PLACEHOLDER", str(VIEWANGLES_RIGHT_DISP))
        .replace("UP_DISP_PLACEHOLDER", str(VIEWANGLES_UP_DISP))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
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
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, PATCH_NAME)
    if output is None:
        return False
    owner_artifact = _function_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner_artifact is None:
        if debug:
            print(f"  {skill_name}: missing {OWNER_FUNC_NAME} artifact")
        return False
    owner_data, owner_ea = owner_artifact
    owner_function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=_function_allows_across_boundary(owner_data),
    )
    if not owner_function or not owner_function.get("func_sig"):
        if debug:
            print(f"  {skill_name}: failed to verify {OWNER_FUNC_NAME} artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_candidates(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: locator failed {located}")
        return False
    candidates = located.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1:
        if debug:
            print(f"  {skill_name}: expected exactly one portal view-vector call, got {candidates}")
        return False
    site = candidates[0]
    if not isinstance(site, dict):
        return False
    target_desc = site.get("target_desc")
    if not isinstance(target_desc, dict) or target_desc.get("name") is None:
        if debug:
            print(f"  {skill_name}: candidate callee is not a resolved function start")
        return False
    try:
        patch_ea = int(site["ea"])
    except (TypeError, ValueError, KeyError):
        return False
    if patch_ea < int(image_base):
        return False
    generated = await run_signature(session, patch_ea)
    if generated is None:
        if debug:
            print(f"  {skill_name}: no unique patch signature at {hex(patch_ea)}")
        return False
    if await _find_unique_bytes(session, generated["patch_sig"]) != patch_ea:
        return False
    if debug:
        print(
            f"  {skill_name}: {PATCH_NAME} ea={hex(patch_ea)} in {site['enclosing']['name']} -> {target_desc['name']}"
        )
    write_patch_yaml(
        output,
        {
            "patch_name": PATCH_NAME,
            "patch_va": hex(patch_ea),
            "patch_rva": hex(patch_ea - int(image_base)),
            "patch_sig": generated["patch_sig"],
            "patch_sig_disp": generated["patch_sig_disp"],
        },
    )
    return True
