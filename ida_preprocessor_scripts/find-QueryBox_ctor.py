#!/usr/bin/env python3
"""Recover GameUI's narrow-string QueryBox constructor from the quit flow.

The target's #QueryBox_Cancel literal is shared by the char and wchar_t
overloads. A quit-title xref instead anchors the current containing Taskbar
body, including builds that inline OnOpenQuitConfirmationDialog into OnCommand.
Pattern D selects its direct constructor call; current-IDB control-flow and
the target-owned cancel token independently check the selected call.
"""

import re
from pathlib import Path

from ida_analyze_util import (
    _call_llm_for_targets,
    _inspect_function_via_mcp,
    _inspect_llm_instruction,
    _load_yaml_mapping,
    _llm_entry_instruction_is_valid,
    _normalize_llm_decompile_specs,
    _output_for_symbol,
    _prepare_llm_context,
    parse_mcp_result,
    write_func_yaml,
)


OWNER = "CTaskbar_QuitConfirmationOwner"
TARGET = "QueryBox_ctor"
REAL_NAME = "vgui2::QueryBox::QueryBox(char const*, char const*, vgui2::Panel*)"
# Expand only when the ordinary in-function wildcarded signature is ambiguous.
SIGNATURE_BYTE_LIMITS = (None, 128, 256, 512)
LLM_DECOMPILE = [
    {
        "symbol_name": TARGET,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/hl-8684/gameui/CTaskbar_QuitConfirmationOwner.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CTaskbar_QuitConfirmationOwner.{platform}.yaml": "required"},
    }
]


def _call_validation_code(owner_va, target_va):
    return f"""
import json, idautils, ida_bytes, ida_funcs, ida_gdl, ida_segment, ida_ua

owner = ida_funcs.get_func({owner_va})
target = ida_funcs.get_func({target_va})
terms = ('#GameUI_QuitConfirmationTitle', '#GameUI_QuitConfirmationText', '#QueryBox_Cancel')
refs = {{term: [] for term in terms}}
for term in terms:
    needle = term.encode() + b'\\0'
    for segment_ea in idautils.Segments():
        segment = ida_segment.getseg(segment_ea)
        if segment.type == ida_segment.SEG_CODE:
            continue
        data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
        if not data:
            continue
        offset = 0
        while True:
            position = data.find(needle, offset)
            if position < 0:
                break
            for xref in idautils.XrefsTo(segment.start_ea + position, 0):
                refs[term].append(int(xref.frm))
            offset = position + 1

valid = bool(owner and target and owner.start_ea == {owner_va} and target.start_ea == {target_va})
calls = []
quit_calls = []
matching_blocks = 0
if valid:
    for instruction_ea in idautils.FuncItems(owner.start_ea):
        instruction = idautils.DecodeInstruction(instruction_ea)
        if (instruction and instruction.get_canon_mnem() == 'call'
                and instruction.ops[0].type in (ida_ua.o_near, ida_ua.o_far)
                and int(instruction.ops[0].addr) == target.start_ea):
            calls.append(int(instruction_ea))
    for block in ida_gdl.FlowChart(owner):
        has_title = False
        has_text = False
        has_call = False
        for ea in refs[terms[0]]:
            if block.start_ea <= ea < block.end_ea:
                has_title = True
        for ea in refs[terms[1]]:
            if block.start_ea <= ea < block.end_ea:
                has_text = True
        for ea in calls:
            if block.start_ea <= ea < block.end_ea:
                has_call = True
                if has_title and has_text:
                    quit_calls.append(ea)
        if has_title and has_text and has_call:
            matching_blocks += 1
    cancel_in_target = False
    for ea in refs[terms[2]]:
        referencing_function = ida_funcs.get_func(ea)
        if referencing_function and referencing_function.start_ea == target.start_ea:
            cancel_in_target = True
    valid = len(quit_calls) == 1 and matching_blocks == 1 and cancel_in_target
result = json.dumps({{'valid': valid, 'calls': calls, 'quit_calls': quit_calls, 'matching_blocks': matching_blocks}})
"""


async def _validate_call(session, owner_va, target_va):
    try:
        raw = await session.call_tool("py_eval", {"code": _call_validation_code(owner_va, target_va)})
        payload = parse_mcp_result(raw)
    except Exception:
        return None
    return payload if isinstance(payload, dict) and payload.get("valid") is True else None


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
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER}.{platform}.yaml")
    if owner is None:
        return False
    specs = _normalize_llm_decompile_specs(LLM_DECOMPILE)
    if specs is None:
        return False
    context = _prepare_llm_context(specs[TARGET], llm_config, new_binary_dir, platform)
    if context is None:
        return False
    result, target_ranges = await _call_llm_for_targets(
        session=session,
        symbol_names=[TARGET],
        specs=specs,
        context=context,
        platform=platform,
        new_binary_dir=new_binary_dir,
        debug=debug,
    )
    entries = [entry for entry in result.get("found_call", ()) if entry.get("func_name") == TARGET]
    if not entries:
        return False
    try:
        owner_va = int(owner["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False

    llm_call_sites = set()
    llm_targets = set()
    for entry in entries:
        detail = await _inspect_llm_instruction(session, entry.get("insn_va"))
        if detail is None or not _llm_entry_instruction_is_valid(entry, detail, target_ranges, ()):
            return False
        actual_line = re.split(r"\s;", str(detail.get("line") or ""), maxsplit=1)[0]
        if (
            detail.get("mnemonic") != "call"
            or " ".join(str(entry.get("insn_disasm") or "").split()).lower() != " ".join(actual_line.split()).lower()
        ):
            return False
        code_refs = detail.get("code_refs")
        if not isinstance(code_refs, list) or len(set(code_refs)) != 1:
            return False
        try:
            if int(detail["func_start"], 0) != owner_va:
                return False
            llm_call_sites.add(int(entry["insn_va"], 0))
            llm_targets.add(int(code_refs[0], 0))
        except (KeyError, TypeError, ValueError):
            return False
    if len(llm_targets) != 1:
        return False
    target_va = next(iter(llm_targets))
    call_validation = await _validate_call(session, owner_va, target_va)
    if call_validation is None or set(call_validation["quit_calls"]) - llm_call_sites:
        return False

    # The char and wchar_t constructors can have identical wildcarded heads.
    # Their call to the corresponding MessageBox overload is the semantic
    # discriminator. Keep that rel32 only after a unique current-IDB match;
    # it is an output signature, never a discovery anchor.
    candidate = None
    for limit in SIGNATURE_BYTE_LIMITS:
        candidate = await _inspect_function_via_mcp(
            session,
            target_va,
            image_base,
            REAL_NAME,
            allow_relative_call_discriminator=True,
            signature_byte_limit=limit,
        )
        if candidate is not None:
            break
    if candidate is None:
        return False
    output = _output_for_symbol(expected_outputs, TARGET)
    if output is None:
        return False
    write_func_yaml(
        output,
        {field: candidate[field] for field in ("func_name", "func_va", "func_rva", "func_size", "func_sig")},
    )
    return True
