#!/usr/bin/env python3
"""Recover startup-image members from CVideoMode_Common::DrawStartupGraphic.

The verified owner implements the same source roles in the GDI, GL, HL25, and
SvEngine families: reject an empty image vector, scale by the base resolution,
and iterate 0x18-byte bimage_t elements.  Most builds expose every requested
member as a direct ``this+disp`` operand and use Pattern E.

CoF 5936 compiles every m_ImageID operation out of line.  Its owner materializes
``&m_ImageID`` with ``add reg, imm`` and calls CUtlVector::Size, whose current
body reads ``[vector+0xC]``.  The deterministic fallback validates that complete
call/result sequence, emits m_ImageID from the immediate, and emits the nested
m_Size as ``m_ImageID + current-binary CUtlVector::m_Size``.  No layout value is
copied from another build, and an old offset artifact is never a discovery path.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact

OWNER = "CVideoMode_Common_DrawStartupGraphic"
STRUCT = "CVideoMode_Common"
MEMBER_BY_SYMBOL = {
    "CVideoMode_Common_m_ImageID": "m_ImageID",
    "CVideoMode_Common_m_ImageID_m_Size": "m_ImageID.m_Size",
    "CVideoMode_Common_m_iBaseResX": "m_iBaseResX",
    "CVideoMode_Common_m_iBaseResY": "m_iBaseResY",
}
MEMBER_NAMES = list(MEMBER_BY_SYMBOL)
IMAGE_SYMBOL = "CVideoMode_Common_m_ImageID"
SIZE_SYMBOL = "CVideoMode_Common_m_ImageID_m_Size"
X_SYMBOL = "CVideoMode_Common_m_iBaseResX"
Y_SYMBOL = "CVideoMode_Common_m_iBaseResY"

HL25_GAMEVER = "hl-10210"
GDI_GAMEVERS = frozenset({"cof-5936", "hl-3248", "hl-3266", "hl-3329", "hl-3647", "hl-4554"})
SVENGINE_REFERENCE = "svencoop-10257"


def _reference_gamever(gamever):
    if gamever == HL25_GAMEVER:
        return HL25_GAMEVER
    if gamever in GDI_GAMEVERS:
        return "hl-3248"
    if gamever.startswith("svencoop-"):
        return SVENGINE_REFERENCE
    return "hl-8684"


def _llm_specs(symbol_names, reference_gamever):
    reference = f"references/{reference_gamever}/engine/{OWNER}.{{platform}}.yaml"
    specs = []
    for name in symbol_names:
        spec = {
            "symbol_name": name,
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [reference],
            "expected_result_sections": ["found_struct_offset"],
            "dependency_policy": {f"{OWNER}.{{platform}}.yaml": "required"},
        }
        if name != IMAGE_SYMBOL:
            spec["expected_size"] = 4
        specs.append(spec)
    return specs


def _desired_fields(symbol_names):
    fields = []
    for name in symbol_names:
        desired = ["struct_name", "member_name", "offset"]
        if name != IMAGE_SYMBOL:
            desired.append("size")
        desired.extend(["offset_sig", "offset_sig_disp"])
        fields.append((name, desired))
    return fields


FALLBACK_QUERY = r"""
import ida_funcs, ida_ua, idaapi, idautils, idc, json
owner_start = OWNER_START_PLACEHOLDER
owner_end = OWNER_END_PLACEHOLDER
globals().update(locals())

def _next_instruction(ea, limit):
    value = idc.next_head(int(ea), int(limit))
    return None if value == idaapi.BADADDR or value >= limit else int(value)

def _decoded(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, int(ea)) > 0 else None

def _displacements(insn):
    values = []
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        if op.type == ida_ua.o_displ:
            values.append(int(op.addr) & 0xffffffff)
    return values

def _register_test_after(load_ea, register, limit):
    ea = load_ea
    for _ in range(5):
        ea = _next_instruction(ea, limit)
        if ea is None:
            return False
        insn = _decoded(ea)
        if insn is None:
            return False
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        if (mnemonic == 'test' and insn.ops[0].type == ida_ua.o_reg
                and insn.ops[1].type == ida_ua.o_reg
                and insn.ops[0].reg == register and insn.ops[1].reg == register):
            return True
        if mnemonic.startswith(('call', 'j', 'ret')):
            return False
        if (insn.ops[0].type == ida_ua.o_reg and insn.ops[0].reg == register
                and mnemonic not in {'cmp', 'test'}):
            return False
    return False

def _direct_size_guard(owner_start=owner_start, owner_end=owner_end):
    candidates = set()
    limit = min(owner_end, owner_start + 0x80)
    for ea in idautils.FuncItems(owner_start):
        if ea >= limit:
            break
        insn = _decoded(ea)
        if insn is None:
            continue
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        for value in _displacements(insn):
            if not (0x100 <= value < 0x400 and value % 4 == 0):
                continue
            if mnemonic == 'cmp':
                candidates.add(value)
            elif mnemonic == 'mov' and insn.ops[0].type == ida_ua.o_reg:
                if _register_test_after(ea, insn.ops[0].reg, limit):
                    candidates.add(value)
    return sorted(candidates)

def _size_member_offset(target):
    function = ida_funcs.get_func(int(target))
    if function is None or int(function.start_ea) != int(target) or int(function.end_ea) - int(target) > 0x40:
        return None
    offsets = set()
    saw_return = False
    for ea in idautils.FuncItems(int(target)):
        insn = _decoded(ea)
        if insn is None:
            return None
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        saw_return = saw_return or mnemonic.startswith('ret')
        if (mnemonic == 'mov' and insn.ops[0].type == ida_ua.o_reg
                and insn.ops[1].type == ida_ua.o_displ
                and insn.ops[1].reg == insn.ops[0].reg):
            value = int(insn.ops[1].addr) & 0xffffffff
            if 0 < value < 0x40 and value % 4 == 0:
                offsets.add(value)
    return next(iter(offsets)) if saw_return and len(offsets) == 1 else None

def _fallback_candidates(owner_start=owner_start, owner_end=owner_end):
    candidates = []
    limit = min(owner_end, owner_start + 0x80)
    for add_ea in idautils.FuncItems(owner_start):
        if add_ea >= limit:
            break
        add_insn = _decoded(add_ea)
        if (add_insn is None or (idc.print_insn_mnem(add_ea) or '').lower() != 'add'
                or add_insn.ops[0].type != ida_ua.o_reg or add_insn.ops[1].type != ida_ua.o_imm):
            continue
        base_offset = int(add_insn.ops[1].value) & 0xffffffff
        if not (0x100 <= base_offset < 0x400 and base_offset % 4 == 0):
            continue
        call_ea = _next_instruction(add_ea, limit)
        call_insn = _decoded(call_ea) if call_ea is not None else None
        if call_insn is None or (idc.print_insn_mnem(call_ea) or '').lower() != 'call':
            continue
        targets = sorted(set(int(value) for value in idautils.CodeRefsFrom(call_ea, 0)))
        if len(targets) != 1:
            continue
        member_offset = _size_member_offset(targets[0])
        if member_offset is None:
            continue
        test_ea = _next_instruction(call_ea, limit)
        test_insn = _decoded(test_ea) if test_ea is not None else None
        if (test_insn is None or (idc.print_insn_mnem(test_ea) or '').lower() != 'test'
                or test_insn.ops[0].type != ida_ua.o_reg or test_insn.ops[1].type != ida_ua.o_reg
                or test_insn.ops[0].reg != test_insn.ops[1].reg):
            continue
        candidates.append({
            'insn_ea': hex(int(add_ea)),
            'base_offset': hex(base_offset),
            'member_offset': hex(member_offset),
            'size_func': hex(targets[0]),
        })
    return candidates

globals().update(locals())
direct = _direct_size_guard()
fallback = [] if direct else _fallback_candidates()
result = json.dumps({'pointer_size': 8 if idaapi.inf_is_64bit() else 4,
                     'direct_size_offsets': direct, 'fallback': fallback})
"""


async def _fallback_candidate(session, owner, debug=False):
    code = FALLBACK_QUERY.replace("OWNER_START_PLACEHOLDER", str(owner["owner_ea"])).replace(
        "OWNER_END_PLACEHOLDER", str(owner["owner_end"])
    )
    try:
        raw_result = await session.call_tool("py_eval", {"code": code})
        payload = parse_mcp_result(raw_result)
        if debug and not payload:
            print(f"validated size-anchor empty raw result: {raw_result!r}")
    except Exception as exc:  # noqa: BLE001 - MCP failures must fail closed.
        if debug:
            print(f"validated size-anchor scan failed: {exc}")
        return None, False
    if debug:
        print(f"validated size-anchor scan: {payload}")
    if not isinstance(payload, dict) or payload.get("pointer_size") != 4:
        return None, False
    direct_offsets = payload.get("direct_size_offsets")
    fallback = payload.get("fallback")
    if not isinstance(direct_offsets, list) or not isinstance(fallback, list):
        return None, False
    if direct_offsets:
        return None, True
    if len(fallback) != 1 or not isinstance(fallback[0], dict):
        return None, False
    try:
        candidate = {
            key: int(fallback[0][key], 0) if isinstance(fallback[0][key], str) else int(fallback[0][key])
            for key in ("insn_ea", "base_offset", "member_offset", "size_func")
        }
    except (KeyError, TypeError, ValueError):
        return None, False
    if candidate["base_offset"] + candidate["member_offset"] >= 0x400:
        return None, False
    return candidate, False


def _remove_outputs(expected_outputs, new_binary_dir):
    root = Path(new_binary_dir).resolve()
    for value in expected_outputs:
        path = Path(value).resolve()
        if path.is_relative_to(root) and path.is_file():
            path.unlink()


def _validate_outputs(expected_outputs, debug=False):
    payloads = {}
    for symbol_name, member_name in MEMBER_BY_SYMBOL.items():
        output = _output_for_symbol(expected_outputs, symbol_name)
        payload = _load_yaml_mapping(output)
        if not payload or payload.get("struct_name") != STRUCT or payload.get("member_name") != member_name:
            if debug:
                print(f"invalid {symbol_name} artifact identity: {payload!r}")
            return False
        try:
            value = payload["offset"]
            payloads[symbol_name] = int(value, 0) if isinstance(value, str) else int(value)
        except (KeyError, TypeError, ValueError):
            if debug:
                print(f"invalid {symbol_name} artifact offset: {payload!r}")
            return False
    image = payloads[IMAGE_SYMBOL]
    size = payloads[SIZE_SYMBOL]
    valid = size == image + 0xC and payloads[X_SYMBOL] == size + 0x8 and payloads[Y_SYMBOL] == size + 0xC
    if debug and not valid:
        print(f"inconsistent CVideoMode_Common layout: {payloads!r}")
    return valid


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
    del old_yaml_map
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER)
    if owner is None:
        return False
    artifact_sig = owner["artifact"].get("func_sig")
    if not artifact_sig or await _find_unique_bytes(session, artifact_sig) != owner["owner_ea"]:
        return False

    fallback, direct_size_available = await _fallback_candidate(session, owner, debug=debug)
    if fallback is None and not direct_size_available:
        if debug:
            print(f"{skill_name}: neither a direct m_Size guard nor the validated CUtlVector fallback was found")
        return False
    llm_targets = MEMBER_NAMES if fallback is None else [X_SYMBOL, Y_SYMBOL]
    gamever = Path(new_binary_dir).resolve().parent.name
    if not await preprocess_common_skill(
        session=session,
        expected_outputs=[
            output
            for output in expected_outputs
            if any(Path(output).name == f"{name}.{platform}.yaml" for name in llm_targets)
        ],
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=llm_targets,
        llm_decompile_specs=_llm_specs(llm_targets, _reference_gamever(gamever)),
        llm_config=llm_config,
        generate_yaml_desired_fields=_desired_fields(llm_targets),
        debug=debug,
    ):
        _remove_outputs(expected_outputs, new_binary_dir)
        return False

    if fallback is not None:
        image_output = _output_for_symbol(expected_outputs, IMAGE_SYMBOL)
        size_output = _output_for_symbol(expected_outputs, SIZE_SYMBOL)
        if image_output is None or size_output is None:
            _remove_outputs(expected_outputs, new_binary_dir)
            return False
        common = {
            "struct_name": STRUCT,
            "offset_sig": owner["function"]["func_sig"],
            "offset_sig_disp": fallback["insn_ea"] - owner["owner_ea"],
            "offset_sig_ref_kind": "immediate",
        }
        if owner["allow_across"]:
            common["offset_sig_allow_across_function_boundary"] = True
        write_struct_offset_yaml(
            image_output,
            {
                **common,
                "member_name": MEMBER_BY_SYMBOL[IMAGE_SYMBOL],
                "offset": hex(fallback["base_offset"]),
            },
        )
        write_struct_offset_yaml(
            size_output,
            {
                **common,
                "member_name": MEMBER_BY_SYMBOL[SIZE_SYMBOL],
                "offset": hex(fallback["base_offset"] + fallback["member_offset"]),
                "size": "4",
                "offset_sig_addend": fallback["member_offset"],
            },
        )

    if not _validate_outputs(expected_outputs, debug=debug):
        _remove_outputs(expected_outputs, new_binary_dir)
        return False
    return True
