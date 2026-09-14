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

import inspect
import json
from pathlib import Path

from ida_analyze_util import (
    _load_yaml_mapping,
    _parse_int,
    parse_mcp_result,
    preprocess_common_skill,
)
from scalar_artifact import SCALAR_FIELDS
import ida_preprocessor_scripts._client_portal_offsets as _client_portal_offsets

PREDECESSOR = "ClientPortalManager_RenderPortals"
REFERENCE = "references/{gamever}/client/ClientPortalManager_RenderPortals.{platform}.yaml"

VECTOR_BEGIN = "ClientPortalManager_vector_begin_offset"
VECTOR_END = "ClientPortalManager_vector_end_offset"
TEXTURE_ID = "ClientPortal_texture_id_offset"
TEXTURE_WIDTH = "ClientPortal_texture_width_offset"
TEXTURE_HEIGHT = "ClientPortal_texture_height_offset"

WALK = r"""
def main(values):
    import idautils, ida_funcs, ida_ua, ida_idp, ida_nalt, idaapi, idc, json, re
    if idaapi.inf_is_64bit():
        return {'error': 'portal walk requires x86-32'}
    func = ida_funcs.get_func(int(values['predecessor']))
    if func is None or int(func.start_ea) != int(values['predecessor']):
        return {'error': 'predecessor is not a function start'}
    imports = {}
    def imported(ea, name, ordinal):
        if name:
            imports[int(ea)] = name.lstrip('_').split('@')[0]
        return True
    for module_index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(module_index, imported)
    insns = []
    addresses = list(idautils.FuncItems(func.start_ea))
    indices = {int(ea): index for index, ea in enumerate(addresses)}
    for ea in idautils.FuncItems(func.start_ea):
        decoded = idautils.DecodeInstruction(ea)
        if decoded is None:
            return {'error': 'instruction decode failed'}
        operands, writes = [], []
        feature = decoded.get_canon_feature()
        for index, op in enumerate(decoded.ops):
            if op.type == ida_ua.o_void:
                break
            operand = {'kind': 'unsupported', 'size': ida_ua.get_dtype_size(op.dtype)}
            text = (idc.print_operand(ea, index) or '').lower()
            if op.type == ida_ua.o_reg:
                operand.update(kind='reg', reg=text)
                if feature & getattr(ida_idp, 'CF_CHG%d' % (index + 1)):
                    # Partial-register writes invalidate the corresponding full register.
                    root = {'al':'eax','ah':'eax','ax':'eax','bl':'ebx','bh':'ebx','bx':'ebx',
                            'cl':'ecx','ch':'ecx','cx':'ecx','dl':'edx','dh':'edx','dx':'edx',
                            'si':'esi','di':'edi','bp':'ebp','sp':'esp'}.get(text, text)
                    writes.append(root)
            elif op.type == ida_ua.o_imm:
                operand.update(kind='imm', value=int(op.value))
            elif op.type == ida_ua.o_mem and int(op.addr) in imports:
                operand.update(kind='api', name=imports[int(op.addr)])
            elif op.type in (ida_ua.o_displ, ida_ua.o_phrase) and 'fs:' not in text and 'gs:' not in text:
                regs = re.findall(r'\be(?:ax|bx|cx|dx|si|di|bp|sp)\b', text)
                if len(regs) == 1 and '*' not in text:
                    disp = int(op.addr) & 0xFFFFFFFF if op.type == ida_ua.o_displ else 0
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    operand.update(kind='mem', base=regs[0], disp=disp)
            operands.append(operand)
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        successors = [indices[int(target)] for target in idautils.CodeRefsFrom(ea, 1) if int(target) in indices]
        insns.append({'mnemonic': mnemonic, 'operands': operands, 'writes': writes, 'successors': successors})
    try:
        return {'pointer_size': 4, **recover_portal_offsets(insns, values['platform'])}
    except ValueError as exc:
        return {'error': str(exc)}
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
    values = json.dumps({"predecessor": predecessor_ea, "platform": platform})
    # The walk body is delivered json-embedded: the remote py_eval executes it
    # through this wrapper, which also surfaces tracebacks instead of an empty
    # payload when the walk body fails inside the worker.
    # Execute the tested helper beside the IDA decoder, keeping the large
    # instruction payload inside the worker (MCP truncates oversized results).
    walk_body = inspect.getsource(_client_portal_offsets) + "\n" + WALK.replace("VALUES", values)
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
