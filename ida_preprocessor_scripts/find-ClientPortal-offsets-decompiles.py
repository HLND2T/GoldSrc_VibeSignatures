#!/usr/bin/env python3
"""Recover the Sven Co-op client portal-manager structural offsets.

Two manager portal-vector offsets are recovered on both platforms from the
verified ClientPortalManager_RenderPortals prologue: the portal vector's
begin/end slots are loaded and compared as the very first loop (Windows
manager+0x8C/+0x90, Linux manager+0x84/+0x88 - the layouts differ between the
MSVC and GCC builds). The three ClientPortal texture offsets are additionally
recovered on Windows: the per-iteration ClientPortal* is reloaded right before
the portal-surface block, its +0xCC slot is tested/used for glGenTextures and
glBindTexture, and +0xD0/+0xD4 are pushed directly as the glTexImage2D
width/height arguments. Each value is verified against the current IDB by the
walk below before the LLM agreement pass; ambiguous provenance (Linux texture
fields, mode/origin/angles) fails closed and stays unemitted.
"""

import json
import re
from pathlib import Path

from ida_analyze_util import (
    _load_yaml_mapping,
    _parse_int,
    parse_mcp_result,
    preprocess_common_skill,
)
from scalar_artifact import SCALAR_FIELDS

PREDECESSOR = "ClientPortalManager_RenderPortals"
REFERENCE = "references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml"

VECTOR_BEGIN = "ClientPortalManager_vector_begin_offset"
VECTOR_END = "ClientPortalManager_vector_end_offset"
TEXTURE_ID = "ClientPortal_texture_id_offset"
TEXTURE_WIDTH = "ClientPortal_texture_width_offset"
TEXTURE_HEIGHT = "ClientPortal_texture_height_offset"

WALK = r"""
def main(values):
    import idautils, ida_funcs, idc, json
    func = ida_funcs.get_func(int(values['predecessor']))
    if func is None:
        return {'error': 'predecessor missing'}
    insns = []
    for ea in idautils.FuncItems(func.start_ea):
        insns.append((int(ea), (idc.print_insn_mnem(ea) or '').lower(),
                      idc.generate_disasm_line(ea, 0) or ''))
    out = {}

    # Vector begin/end: within the first 40 instructions, a manager-base pair
    # whose two slot loads are compared against each other.
    for i in range(min(40, len(insns))):
        ea, mnem, line = insns[i]
        if mnem != 'mov':
            continue
        m1 = re.search(r'mov\s+(\w+), \[(\w+)\+([0-9A-Fa-f]+)h?\]', line)
        if not m1:
            continue
        rx, rm, d1s = m1.group(1), m1.group(2), m1.group(3)
        d1 = int(d1s.rstrip('h'), 16)
        for j in range(i + 1, min(i + 16, len(insns))):
            _, mnem2, line2 = insns[j]
            if mnem2 != 'cmp':
                continue
            pair = None
            m2 = re.search(r'cmp\s+%s, \[(%s)\+([0-9A-Fa-f]+)h?\]' % (rx, rm), line2)
            m3 = re.search(r'cmp\s+\[(%s)\+([0-9A-Fa-f]+)h?\], %s' % (rm, rx), line2)
            m4 = re.search(r'cmp\s+%s, (\w+)' % rx, line2)
            if m2:
                pair = int(m2.group(2).rstrip('h'), 16)
            elif m3:
                pair = int(m3.group(2).rstrip('h'), 16)
            elif m4:
                ry = m4.group(1)
                for k in range(i + 1, j):
                    mk = re.search(r'mov\s+%s, \[%s\+([0-9A-Fa-f]+)h?\]' % (ry, rm), insns[k][2])
                    if mk:
                        pair = int(mk.group(1).rstrip('h'), 16)
                        break
            if pair is not None and pair - d1 == 4:
                out['vector_begin'] = d1
                out['vector_end'] = pair
                break
        if 'vector_begin' in out:
            break
    if 'vector_begin' not in out:
        return {'error': 'vector loop not found'}

    # Texture triple (Windows shape): the portal pointer reload is followed by
    # a test of portal+T and lea of the same slot, then pushes of portal+T+4
    # and portal+T+8 directly as glTexImage2D width/height.
    for i in range(len(insns)):
        _, mnem, line = insns[i]
        if mnem != 'cmp':
            continue
        m5 = re.search(r'cmp\s+(?:dword ptr )?\[(\w+)\+([0-9A-Fa-f]+)h?\], 0', line)
        if not m5:
            continue
        base, ts = m5.group(1), m5.group(2)
        t = int(ts.rstrip('h'), 16)
        window = insns[i + 1:i + 4]
        if not any(re.search(r'lea\s+\w+, \[%s\+%sh?\]' % (base, ts), w[2]) for w in window):
            continue
        pushed = set()
        for _, _, lw in insns:
            for mm in re.finditer(r'push\s+(?:dword ptr )?\[\w+\+([0-9A-Fa-f]+)h?\]', lw):
                pushed.add(int(mm.group(1).rstrip('h'), 16))
        if {t + 4, t + 8} <= pushed:
            out['texture_id'] = t
            out['texture_width'] = t + 4
            out['texture_height'] = t + 8
            break
    return {'pointer_size': 4, **out}
import re
import json
result = json.dumps(main(VALUES))
"""


def _llm_spec(symbol_name, expected_value):
    return {
        "symbol_name": symbol_name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [REFERENCE],
        "expected_result_sections": ["found_scalar"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
        "expected_value": expected_value,
    }


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    _ = skill_name, old_yaml_map
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"{PREDECESSOR}.{platform}.yaml")
    if not predecessor or predecessor.get("func_name") != PREDECESSOR:
        return False
    try:
        predecessor_ea = _parse_int(predecessor.get("func_va"), "func_va")
    except Exception:  # noqa: BLE001 - malformed dependency fails closed.
        return False
    if predecessor_ea < int(image_base):
        return False
    values = json.dumps({"predecessor": predecessor_ea})
    # The walk body is delivered json-embedded: the remote py_eval executes it
    # through this wrapper, which also surfaces tracebacks instead of an empty
    # payload when the walk body fails inside the worker.
    walk_body = WALK.replace("VALUES", values)
    wrapper = (
        "def _main():\n"
        "    import json, traceback\n"
        "    ns = {'__name__': 'walk'}\n"
        "    try:\n"
        "        exec(" + json.dumps(walk_body) + ", ns)\n"
        "        return ns.get('result')\n"
        "    except Exception:\n"
        "        return {'error': traceback.format_exc()[-800:]}\n"
        "_main()\n"
    )
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": wrapper}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print("ClientPortal offset walk failed:", located)
        return False

    verified = {
        VECTOR_BEGIN: located.get("vector_begin"),
        VECTOR_END: located.get("vector_end"),
        TEXTURE_ID: located.get("texture_id"),
        TEXTURE_WIDTH: located.get("texture_width"),
        TEXTURE_HEIGHT: located.get("texture_height"),
    }
    scalar_names = [name for name, value in verified.items() if isinstance(value, int)]
    if not scalar_names:
        return False
    specs = [_llm_spec(name, verified[name]) for name in scalar_names]
    if debug:
        print("ClientPortal verified offsets:", {name: verified[name] for name in scalar_names})
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        scalar_names=scalar_names,
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, list(SCALAR_FIELDS)) for name in scalar_names],
        debug=debug,
    )
