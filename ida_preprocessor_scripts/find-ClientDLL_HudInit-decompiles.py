#!/usr/bin/env python3
"""Locate client-engine globals used while initializing the client DLL.

``cl_enginefuncs`` and ``g_ppExportFuncs`` are the two operands of the
``cl_funcs.pInitFunc(CLDLL_INTERFACE_VERSION, &cl_enginefuncs)`` call in
``ClientDLL_Init``. Locate that call directly so large Linux function bodies
do not have to pass through the LLM export transport.

``g_phClientModule`` remains an LLM_DECOMPILE target because the verified
``ClientDLL_HudInit`` predecessor is small and its platform-specific access is
already annotated in the canonical reference.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
    write_gv_yaml,
)


DIRECT_GV_NAMES = ["cl_enginefuncs", "g_ppExportFuncs"]
LLM_GV_NAMES = ["g_phClientModule"]
OWNER_FUNC_NAME = "ClientDLL_Init"
CLIENT_DLL_INTERFACE_VERSION = 7

LLM_DECOMPILE = [
    {
        "symbol_name": "g_phClientModule",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/ClientDLL_HudInit.{platform}.yaml",
        ],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {
            "ClientDLL_HudInit.{platform}.yaml": "required",
        },
    }
]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary?",
]
GENERATE_YAML_DESIRED_FIELDS = [(symbol_name, GV_FIELDS) for symbol_name in LLM_GV_NAMES]


LOCATE_INIT_GLOBALS_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER
INTERFACE_VERSION = INTERFACE_VERSION_PLACEHOLDER

def writable_data_segment(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None:
        return False
    perms = int(getattr(seg, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return bool(perms & writable) and not bool(perms & executable)

def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None

def encoded_absolute_operand(ea, allowed_types):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return None
    raw = ida_bytes.get_bytes(int(ea), int(insn.size)) or b''
    candidates = []
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            break
        if op_type not in allowed_types:
            continue
        value = int(op.addr if op_type == int(idaapi.o_mem) else op.value) & 0xFFFFFFFF
        offb = int(getattr(op, 'offb', 0))
        if offb <= 0 or offb + 4 > int(insn.size):
            continue
        encoded = int.from_bytes(raw[offb:offb + 4], 'little', signed=False)
        if encoded != value or (value & 3) or not writable_data_segment(value):
            continue
        candidates.append((value, offb))
    if len(candidates) != 1:
        return None
    value, offb = candidates[0]
    return {
        'gv_ea': value,
        'insn_ea': int(ea),
        'insn_len': int(insn.size),
        'insn_disp': offb,
        'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
        'gv_seg': seg_name(value),
    }

def has_interface_version_before(ea, lower_bound):
    cursor = int(ea)
    for _ in range(4):
        cursor = int(ida_bytes.prev_head(cursor, int(lower_bound)))
        if cursor == int(idaapi.BADADDR) or cursor < int(lower_bound):
            return False
        insn = idautils.DecodeInstruction(cursor)
        if not insn:
            continue
        for op in insn.ops:
            op_type = int(op.type)
            if op_type == int(idaapi.o_void):
                break
            if op_type == int(idaapi.o_imm) and (int(op.value) & 0xFFFFFFFF) == INTERFACE_VERSION:
                return True
    return False

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('ClientDLL_Init is not a function start')
    candidates = []
    for call_ea in idautils.FuncItems(int(owner.start_ea)):
        if (idc.print_insn_mnem(int(call_ea)) or '').lower() != 'call':
            continue
        export_hit = encoded_absolute_operand(int(call_ea), {int(idaapi.o_mem)})
        if export_hit is None:
            continue
        engine_ea = int(ida_bytes.prev_head(int(call_ea), int(owner.start_ea)))
        if engine_ea == int(idaapi.BADADDR) or engine_ea < int(owner.start_ea):
            continue
        engine_hit = encoded_absolute_operand(engine_ea, {int(idaapi.o_imm)})
        if engine_hit is None or engine_hit['gv_ea'] == export_hit['gv_ea']:
            continue
        if not has_interface_version_before(engine_ea, int(owner.start_ea)):
            continue
        candidates.append({'engine': engine_hit, 'exports': export_hit})
    if len(candidates) != 1:
        result = json.dumps({
            'error': 'ClientDLL interface initialization call is not unique',
            'owner_ea': hex(int(owner.start_ea)),
            'candidate_count': len(candidates),
            'candidates': candidates,
        })
    else:
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(owner.start_ea)),
            **candidates[0],
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _owner_artifact(new_binary_dir, platform):
    path = Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        return None
    try:
        func_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return None
    return artifact, func_ea


async def _locate_init_globals(session, owner_ea):
    code = LOCATE_INIT_GLOBALS_PY.replace("OWNER_EA_PLACEHOLDER", str(int(owner_ea))).replace(
        "INTERFACE_VERSION_PLACEHOLDER", str(CLIENT_DLL_INTERFACE_VERSION)
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    return payload if isinstance(payload, dict) else None


async def _write_direct_globals(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    debug,
):
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in DIRECT_GV_NAMES}
    if any(output is None for output in outputs.values()):
        return False
    owner_artifact = _owner_artifact(new_binary_dir, platform)
    if owner_artifact is None:
        if debug:
            print("  find-ClientDLL_HudInit-decompiles: missing ClientDLL_Init artifact")
        return False
    artifact, owner_ea = owner_artifact
    allow_across = bool(artifact.get("func_sig_allow_across_function_boundary"))
    owner_function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=allow_across,
    )
    if not owner_function or not owner_function.get("func_sig"):
        if debug:
            print("  find-ClientDLL_HudInit-decompiles: failed to verify ClientDLL_Init artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_init_globals(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-ClientDLL_HudInit-decompiles: direct locator failed {located}")
        return False
    try:
        located_owner_ea = int(located["owner_ea"], 0)
        hits = {
            "cl_enginefuncs": located["engine"],
            "g_ppExportFuncs": located["exports"],
        }
        parsed = {
            name: {
                "gv_ea": int(hit["gv_ea"]),
                "insn_ea": int(hit["insn_ea"]),
                "insn_len": int(hit["insn_len"]),
                "insn_disp": int(hit["insn_disp"]),
            }
            for name, hit in hits.items()
        }
    except (KeyError, TypeError, ValueError):
        return False
    if located_owner_ea != owner_ea or any(
        values["gv_ea"] < int(image_base) or values["insn_ea"] < owner_ea for values in parsed.values()
    ):
        return False
    payloads = {}
    for name, values in parsed.items():
        payload = {
            "gv_name": name,
            "gv_va": hex(values["gv_ea"]),
            "gv_rva": hex(values["gv_ea"] - int(image_base)),
            "gv_sig": owner_function["func_sig"],
            "gv_sig_va": owner_function["func_va"],
            "gv_inst_offset": hex(values["insn_ea"] - owner_ea),
            "gv_inst_length": hex(values["insn_len"]),
            "gv_inst_disp": hex(values["insn_disp"]),
        }
        if allow_across:
            payload["gv_sig_allow_across_function_boundary"] = True
        payloads[name] = payload
    if debug:
        for name, hit in hits.items():
            print(
                f"  find-ClientDLL_HudInit-decompiles: {name}={hit['gv_ea']} "
                f"seg={hit.get('gv_seg')} insn={hit['insn_ea']} {hit.get('insn_disasm', '')}"
            )
    for name, output in outputs.items():
        write_gv_yaml(output, payloads[name])
    return True


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
    if platform not in {"windows", "linux"}:
        return False
    if not await _write_direct_globals(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        debug,
    ):
        return False
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=LLM_GV_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
