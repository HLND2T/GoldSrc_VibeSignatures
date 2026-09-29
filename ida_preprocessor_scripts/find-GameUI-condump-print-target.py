#!/usr/bin/env python3
"""Find the concrete print call in GameUI's condump failure path.

Older Windows builds call CGameConsoleDialog::Print; newer Windows builds and
Linux inline that helper and call vgui2::RichText::InsertString(char const*)
directly. Annotated source-era reference bodies identify the appropriate
call without assuming a call ordinal or fixed instruction address.
"""

from pathlib import Path

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
    write_func_yaml,
)


OWNER = "CGameConsoleDialog_DumpConsoleTextToFile"
PRINT = "CGameConsoleDialog_Print"
INSERT = "GameUI_RichText_InsertStringA"
OLD_WINDOWS = {"hl-3248", "hl-3266", "hl-3329", "hl-3647", "hl-4554", "hl-6153", "hl-8684", "cof-5936"}
REAL_NAMES = {
    PRINT: "CGameConsoleDialog::Print(char const*)",
    INSERT: "vgui2::RichText::InsertString(char const*)",
}


def _gamever(new_binary_dir):
    return Path(new_binary_dir).parent.name


def _reference(gamever, platform):
    # Both reference revisions are source-restored and annotated at the
    # condump failure branch. The older Linux reference retains its distinct
    # failure call; the newer one records the shared success/failure block.
    era = "hl-8684" if (gamever in OLD_WINDOWS or gamever == "hl-8684") else "hl-10210"
    return f"references/{era}/gameui/{OWNER}.{platform}.yaml"


def _body_validation_code(owner_va, target_va, target):
    return f"""
import json, idautils, ida_funcs, ida_ua

owner = ida_funcs.get_func({owner_va})
target = ida_funcs.get_func({target_va})
valid = bool(owner and target and owner.start_ea == {owner_va} and target.start_ea == {target_va})
owner_calls = []
direct_calls = set()
hash_compare = False
if valid:
    for ea in idautils.FuncItems(owner.start_ea):
        insn = idautils.DecodeInstruction(ea)
        if (insn and insn.get_canon_mnem() == 'call'
                and insn.ops[0].type in (ida_ua.o_near, ida_ua.o_far)
                and int(insn.ops[0].addr) == target.start_ea):
            owner_calls.append(int(ea))
    for ea in idautils.FuncItems(target.start_ea):
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        if (insn.get_canon_mnem() == 'call'
                and insn.ops[0].type in (ida_ua.o_near, ida_ua.o_far)):
            direct_calls.add(int(insn.ops[0].addr))
        if insn.get_canon_mnem() == 'cmp':
            for op in insn.ops:
                if op.type == ida_ua.o_imm and (int(op.value) & 0xffffffff) == 0x23:
                    hash_compare = True
    valid = bool(owner_calls) and ({target!r} == '{PRINT}' and len(direct_calls) >= 2 or {target!r} == '{INSERT}' and hash_compare)
result = json.dumps({{'valid': valid, 'owner_calls': owner_calls, 'direct_call_count': len(direct_calls), 'hash_compare': hash_compare}})
"""


async def _validate_body(session, owner_va, target_va, target):
    try:
        payload = parse_mcp_result(
            await session.call_tool("py_eval", {"code": _body_validation_code(owner_va, target_va, target)})
        )
    except Exception:
        return False
    return isinstance(payload, dict) and payload.get("valid") is True


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
    gamever = _gamever(new_binary_dir)
    target = PRINT if platform == "windows" and gamever in OLD_WINDOWS else INSERT
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER}.{platform}.yaml")
    output = _output_for_symbol(expected_outputs, target)
    if owner is None or output is None:
        return False
    spec = {
        "symbol_name": target,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [_reference(gamever, platform)],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {f"{OWNER}.{{platform}}.yaml": "required"},
    }
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[target],
        llm_decompile_specs=[spec],
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            (
                target,
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                    "func_sig_allow_across_function_boundary:true",
                ],
            )
        ],
        debug=debug,
    )
    if not found:
        return False
    data = _load_yaml_mapping(output)
    try:
        owner_va = int(str(owner["func_va"]), 0)
        target_va = int(str(data["func_va"]), 0)
    except (KeyError, TypeError, ValueError):
        Path(output).unlink(missing_ok=True)
        return False
    if not await _validate_body(session, owner_va, target_va, target):
        Path(output).unlink(missing_ok=True)
        return False
    data["func_name"] = REAL_NAMES[target]
    write_func_yaml(output, data)
    return True
