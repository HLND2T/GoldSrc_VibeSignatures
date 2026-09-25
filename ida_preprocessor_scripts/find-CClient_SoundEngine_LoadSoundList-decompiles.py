#!/usr/bin/env python3
"""Recover CClient_SoundEngine's loaded-sentence counter from LoadSoundList.

The Sven Co-op client sound engine keeps its parsed sentences in a fixed
2048-entry pointer table at the start of the object and the number of
occupied entries in a separate int member.  While reading the
"SENTENCELIST {" block, LoadSoundList stops once the table is full:

    if (m_iSentenceCount >= 2048) break;

MSVC emits ``cmp dword ptr [this+disp], 800h; jge`` and GCC emits
``cmp dword ptr [this+disp], 7FFh; jle/jg``.  The finder first proves, in the
current IDB, that the verified LoadSoundList body owns exactly one dword
member compare against the table capacity (0x800 / 0x7FF) that is immediately
tested by the matching signed branch.  That single instruction is the only
one the LLM_DECOMPILE pass may return (``instruction_rules``), and the emitted
offset, instruction and identity must agree with the deterministic evidence.
No value is copied from another build or from an old artifact.

The Linux client has image base 0, so 0x11B09C also lands inside .text and
IDA renders the member operand as a code label (``ds:loc_11B09C[edi]``).  The
LLM validator only accepts numeric displacements, so the verified operand is
switched to a hex number before the target function is exported; the
analyzer's warm IDB session is not saved.

MetaHookSv CaptionMod consumes the same member as
``ScClient_soundengine_maxsentences`` (a byte offset from the engine object,
used as the loop bound when looking up a sentence by name).  The member is a
count, not a capacity: the capacity is the 0x800 immediate above.
"""

import json
import re
from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
)
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact

OWNER = "CClient_SoundEngine_LoadSoundList"
STRUCT = "CClient_SoundEngine"
MEMBER = "m_iSentenceCount"
SYMBOL = f"{STRUCT}_{MEMBER}"
MEMBER_SIZE = 4
# The sentence table holds 2048 entries; ">= 2048" and "> 2047" are both valid
# encodings of the same capacity guard.
CAPACITY_BRANCHES = {0x800: ("jge", "jl"), 0x7FF: ("jg", "jle")}

GUARD_QUERY = r"""
import json
def main(owner_start, owner_end, capacity_branches):
    import ida_bytes, ida_funcs, ida_lines, ida_ua, idautils, idc
    def render(ea):
        return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '').split(';', 1)[0].strip()
    fn = ida_funcs.get_func(owner_start)
    if fn is None or int(fn.start_ea) != owner_start:
        return {'error': 'owner is not a function start'}
    candidates = []
    for ea in idautils.FuncItems(owner_start):
        if not owner_start <= ea < owner_end:
            continue
        if (idc.print_insn_mnem(ea) or '').lower() != 'cmp':
            continue
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            continue
        member, limit = insn.ops[0], insn.ops[1]
        if member.type != ida_ua.o_displ or member.dtype != ida_ua.dt_dword or limit.type != ida_ua.o_imm:
            continue
        branches = capacity_branches.get(str(int(limit.value) & 0xFFFFFFFF))
        if branches is None:
            continue
        branch_ea = idc.next_head(ea, owner_end)
        if branch_ea == idc.BADADDR or branch_ea >= owner_end:
            continue
        branch = (idc.print_insn_mnem(branch_ea) or '').lower()
        if branch not in branches:
            continue
        candidates.append({
            'insn_ea': hex(ea),
            'offset': hex(int(member.addr) & 0xFFFFFFFF),
            'limit': hex(int(limit.value) & 0xFFFFFFFF),
            'branch': branch,
        })
    normalized = False
    if len(candidates) == 1:
        ea = int(candidates[0]['insn_ea'], 16)
        # An image-base-0 ELF can place the member displacement on a code
        # label, so IDA renders "ds:loc_XXXX[reg]". Show the verified member
        # operand as a number (session-only; the analyzer does not save).
        if ida_bytes.is_off(ida_bytes.get_full_flags(ea), 0):
            normalized = bool(ida_bytes.op_hex(ea, 0))
        candidates[0]['line'] = render(ea)
    return {'pointer_size': 4, 'candidates': candidates, 'normalized_operand': normalized}
result = json.dumps(main(OWNER_START, OWNER_END, CAPACITY_BRANCHES))
"""


def _instruction_rule(line):
    return {
        "regex": r"(?i)" + r"\s+".join(re.escape(token) for token in line.split()),
        "text": (
            "Return only this current-target instruction, proven to be LoadSoundList's sentence-table "
            f"capacity guard on the loaded-sentence counter: {line}. Report its displacement as the "
            f"{STRUCT}::{MEMBER} offset with size {MEMBER_SIZE}; reject every other member access."
        ),
    }


async def _verified_guard(session, owner, debug=False):
    code = (
        GUARD_QUERY.replace("OWNER_START", str(owner["owner_ea"]))
        .replace("OWNER_END", str(owner["owner_end"]))
        .replace(
            "CAPACITY_BRANCHES",
            json.dumps({str(limit): list(branches) for limit, branches in CAPACITY_BRANCHES.items()}),
        )
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception as exc:  # noqa: BLE001 - MCP failures must fail closed.
        if debug:
            print(f"{SYMBOL}: capacity-guard scan failed: {exc}")
        return None
    if debug:
        print(f"{SYMBOL}: capacity-guard scan: {payload}")
    if not isinstance(payload, dict) or payload.get("pointer_size") != 4:
        return None
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1 or not isinstance(candidates[0], dict):
        return None
    try:
        guard = {
            "insn_ea": int(candidates[0]["insn_ea"], 0),
            "offset": int(candidates[0]["offset"], 0),
            "line": str(candidates[0]["line"]),
        }
    except (KeyError, TypeError, ValueError):
        return None
    if guard["offset"] <= 0 or guard["offset"] % MEMBER_SIZE or not guard["line"]:
        return None
    return guard


def _remove_output(output):
    if output is not None and Path(output).is_file():
        Path(output).unlink()


def _artifact_matches(output, owner, guard, debug=False):
    payload = _load_yaml_mapping(output)
    try:
        matches = (
            payload.get("struct_name") == STRUCT
            and payload.get("member_name") == MEMBER
            and int(str(payload["offset"]), 0) == guard["offset"]
            and int(str(payload["size"]), 0) == MEMBER_SIZE
            and int(str(payload["offset_sig_disp"]), 0) == guard["insn_ea"] - owner["owner_ea"]
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        matches = False
    if debug and not matches:
        print(f"{SYMBOL}: artifact disagrees with the verified capacity guard: {payload!r} vs {guard!r}")
    return matches


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
    output = _output_for_symbol(expected_outputs, SYMBOL)
    if output is None:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER)
    if owner is None:
        return False
    owner_sig = owner["artifact"].get("func_sig")
    if not owner_sig or await _find_unique_bytes(session, owner_sig) != owner["owner_ea"]:
        return False
    guard = await _verified_guard(session, owner, debug=debug)
    if guard is None:
        if debug:
            print(f"{SYMBOL}: no unique sentence-table capacity guard in {OWNER}")
        return False

    spec = {
        "symbol_name": SYMBOL,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/client/{OWNER}.{{platform}}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {f"{OWNER}.{{platform}}.yaml": "required"},
        "expected_size": MEMBER_SIZE,
        "instruction_rules": [_instruction_rule(guard["line"])],
    }
    if not await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=[SYMBOL],
        llm_decompile_specs=[spec],
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            (SYMBOL, ["struct_name", "member_name", "offset", "size", "offset_sig", "offset_sig_disp"]),
        ],
        debug=debug,
    ):
        _remove_output(output)
        return False
    if not _artifact_matches(output, owner, guard, debug=debug):
        _remove_output(output)
        return False
    return True
