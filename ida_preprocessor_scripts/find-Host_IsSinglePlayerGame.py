#!/usr/bin/env python3
"""Locate Host_IsSinglePlayerGame, the engine single-player predicate.

Source semantics (engine/host.c): ``qboolean Host_IsSinglePlayerGame(void)
{ if (sv.active) return svs.maxclients == 1; else return cl.maxclients == 1; }``.
studioapi_SetupPlayerModel gates its model reload on
``( developer.value || !Host_IsSinglePlayerGame() )`` (engine/r_studio.c), so
the consumed artifact of that function is the anchor.

The locator accepts the unique direct call inside the owner body that:

* returns a consumed boolean: ``test eax, eax`` within the next two
  instructions and a conditional jump right after it;
* targets a small (<= 96 bytes) no-argument callee whose body produces the
  ``== 1`` boolean (``setz``/``sete``, or the ``dec/neg/sbb/inc`` trick used
  by hl-8684 hw.dll through a shared maxclients helper);
* makes no indirect calls and at most one direct call;
* has >= 8 code xrefs (Host_IsSinglePlayerGame is called from ~11 source
  sites across cl_parsefn/cl_main/host/r_studio/sv_main/view).

This rejects the function's other callees on every validated build:
Q_stricmp/Q_strncpy/snprintf/Mod_ForName-style helpers carry arguments or
compare loops, FS_FileExists (SvEngine) calls the filesystem interface, and
R_StudioChangePlayerModel ignores its return value. Validated on
hl-3248..hl-10210, cof-5936, and svencoop-10257 (both platforms where
shipped); the two DWARF-annotated official hw.so builds name the recovered
function directly.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNC_NAME = "Host_IsSinglePlayerGame"
OWNER_FUNC_NAME = "studioapi_SetupPlayerModel"

LOCATE_PY = r"""
import ida_funcs
import ida_idp
import idaapi
import idautils
import idc
import json
import traceback

SETUP_EA = SETUP_EA_PLACEHOLDER
MAX_CALLEE_SIZE = 96
MIN_XREFS = 8

def func_items(start):
    fn = ida_funcs.get_func(int(start))
    if fn is None:
        return []
    return [ea for ea in idautils.FuncItems(int(fn.start_ea))]

def disasm(ea):
    return idc.generate_disasm_line(int(ea), 0) or ''

def squeezed(text):
    return ''.join(str(text).split())

def code_xref_count(ea):
    count = 0
    for ref in idautils.XrefsTo(int(ea), 0):
        if ref.iscode:
            count += 1
    return count

def callee_matches(target):
    fn = ida_funcs.get_func(int(target))
    if fn is None or int(fn.start_ea) != int(target):
        return None
    size = int(fn.end_ea) - int(fn.start_ea)
    if not (0 < size <= MAX_CALLEE_SIZE):
        return None
    body = []
    has_setcc = False
    has_dec = False
    has_sbb = False
    direct_calls = 0
    indirect_calls = 0
    for ea in func_items(target):
        text = disasm(ea)
        body.append(text)
        insn = idautils.DecodeInstruction(int(ea))
        mnem = insn.get_canon_mnem() if insn else ''
        if 'setz' in text or 'sete' in text:
            has_setcc = True
        if mnem == 'dec':
            has_dec = True
        if mnem == 'sbb':
            has_sbb = True
        if mnem == 'call':
            direct = False
            if insn:
                for op in insn.ops:
                    if int(op.type) == int(idaapi.o_void):
                        break
                    if int(op.type) == int(idaapi.o_near):
                        direct = True
            if direct:
                direct_calls += 1
            else:
                indirect_calls += 1
    if indirect_calls or direct_calls > 1:
        return None
    if not (has_setcc or (has_dec and has_sbb)):
        return None
    return {'size': size, 'body_head': body[:6], 'direct_calls': direct_calls}

def main():
    fn = ida_funcs.get_func(SETUP_EA)
    if fn is None or int(fn.start_ea) != SETUP_EA:
        return {'error': 'studioapi_SetupPlayerModel is not a function start'}
    items = func_items(SETUP_EA)
    texts = {ea: disasm(ea) for ea in items}
    candidates = []
    for index, ea in enumerate(items):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn or insn.get_canon_mnem() != 'call':
            continue
        target = None
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_near):
                target = int(op.addr)
        if target is None:
            continue
        window = [texts[x] for x in items[index + 1:index + 6]]
        test_pos = None
        for offset, text in enumerate(window[:2]):
            if squeezed(text).startswith('testeax,eax'):
                test_pos = offset
                break
        if test_pos is None:
            continue
        taken = False
        for text in window[test_pos + 1:test_pos + 4]:
            if squeezed(text)[:1] == 'j':
                taken = True
                break
        if not taken:
            continue
        info = callee_matches(target)
        if info is None:
            continue
        if code_xref_count(target) < MIN_XREFS:
            continue
        candidates.append({
            'call_ea': int(ea),
            'host_va': int(target),
            'callee_size': info['size'],
            'callee_head': info['body_head'],
            'xrefs': code_xref_count(target),
        })
    if len(candidates) != 1:
        return {'error': 'Host_IsSinglePlayerGame candidates: %d' % len(candidates),
                'candidates': [{'call_ea': hex(c['call_ea']), 'host_va': hex(c['host_va'])} for c in candidates]}
    chosen = candidates[0]
    return {
        'pointer_size': 4,
        'setup_va': hex(SETUP_EA),
        'call_ea': hex(chosen['call_ea']),
        'call_disasm': texts[chosen['call_ea']],
        'host_va': hex(chosen['host_va']),
        'callee_size': chosen['callee_size'],
        'callee_head': chosen['callee_head'],
        'xrefs': chosen['xrefs'],
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


def _owner_artifact(new_binary_dir, platform, func_name, image_base):
    path = Path(new_binary_dir) / f"{func_name}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
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


async def _locate_host_is_single_player_game(session, setup_ea):
    try:
        code = LOCATE_PY.replace("SETUP_EA_PLACEHOLDER", str(int(setup_ea)))
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    required = ("call_ea", "host_va")
    if any(field not in payload for field in required):
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
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    if output is None:
        return False
    owner = _owner_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner is None:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: missing {OWNER_FUNC_NAME} artifact")
        return False
    _owner_data, setup_ea = owner
    located = await _locate_host_is_single_player_game(session, setup_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: locator failed {located}")
        return False
    try:
        host_ea = int(located["host_va"], 0)
    except (TypeError, ValueError):
        return False
    if host_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, host_ea, image_base, TARGET_FUNC_NAME)
    allow_across = False
    if not function or not function.get("func_sig"):
        # Tiny bodies (hl-8684 hw.dll is a 12-byte == 1 trampoline) may not
        # produce a unique signature inside the function alone; the
        # across-boundary window keeps the same entry and grows the extent.
        function = await _inspect_function_via_mcp(
            session, host_ea, image_base, TARGET_FUNC_NAME, allow_across_function_boundary=True
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  find-{TARGET_FUNC_NAME}: failed to inspect {located['host_va']}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != host_ea:
        return False
    if debug:
        print(
            f"  find-{TARGET_FUNC_NAME}: func={located['host_va']} "
            f"size={located.get('callee_size')} xrefs={located.get('xrefs')} "
            f"call={located.get('call_disasm', '')}"
        )
    payload = {
        "func_name": TARGET_FUNC_NAME,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
