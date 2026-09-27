#!/usr/bin/env python3
"""Recover three client-state field addresses from model interpolation.

engine/cl_ents.c returns early for ``cls.timedemo`` and then, after the
single-player check, for ``cl.moving && cl.onground == e->index``. These are
members of mapped ``cls`` and ``cl`` objects, not standalone ELF symbols. The
owning instruction is selected by its zero-test or current-binary member
access, and the shared x86 decoder resolves MSVC absolute and GCC PIC forms.
The already-covered ``cl_waterlevel`` field supplies a source-level adjacency
cross-check (client.h: onground, moving, waterlevel are consecutive int32s);
its current artifact signature is revalidated before use. No build address or
whole-struct offset participates in discovery. hl-8684 Linux places timedemo
in the public wrapper and the other fields in its private interpolation core.
"""

from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_entity_interpolation_common import function_identity
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

INTERPOLATOR = "CL_InterpolateModel"
SPLIT_CORE = "CL_InterpolateModel.part.1"
WATERLEVEL = "cl_waterlevel"
TIMEDEMO = "cls_timedemo"
MOVING = "cl_moving"
ONGROUND = "cl_onground"

WALK = r"""
import idaapi

wrapper = int(values['wrapper'], 0)
core = int(values['core'], 0)
waterlevel = int(values['waterlevel'], 0)
moving = waterlevel - 4
onground = waterlevel - 8
wrapper_entries = scan(wrapper)
core_entries = scan(core)

def is_zero_checked(index, entries):
    entry = entries[index]
    insn = entry['insn']
    def branches_on_zero(check_index):
        # MSVC may interleave pose-copy MOVs between TEST and Jcc. They leave
        # EFLAGS intact; any other intervening operation invalidates the link.
        for following in entries[check_index + 1:]:
            if following['mnem'] in ('je', 'jne', 'jz', 'jnz'):
                return True
            if following['mnem'] not in ('mov', 'lea', 'nop', 'push', 'pop'):
                return False
        return False

    if entry['mnem'] == 'cmp' and any(
        int(op.type) == int(idaapi.o_imm) and int(op.value) == 0
        for op in insn.ops):
        return branches_on_zero(index)
    if entry['mnem'] != 'mov' or int(insn.ops[0].type) != int(idaapi.o_reg):
        return False
    name = reg4(insn.ops[0])
    for check_index in range(index + 1, len(entries)):
        check = entries[check_index]
        ops = check['insn'].ops
        if check['mnem'] == 'test' and reg4(ops[0]) == name and reg4(ops[1]) == name:
            return branches_on_zero(check_index)
        if (check['mnem'] == 'cmp' and reg4(ops[0]) == name
                and int(ops[1].type) == int(idaapi.o_imm) and int(ops[1].value) == 0):
            return branches_on_zero(check_index)
        if check['mnem'] in ('call', 'ret', 'jmp'):
            return False
        if (int(ops[0].type) == int(idaapi.o_reg) and reg4(ops[0]) == name
                and changed_operand(check['insn'], 0)):
            return False
    return False

if wrapper_entries is None or core_entries is None:
    result = {'error': 'interpolation function boundary is missing'}
else:
    stars = [i for i, entry in enumerate(wrapper_entries) if entry['mnem'] == 'cmp'
             and any(int(op.type) == int(idaapi.o_imm) and int(op.value) == ord('*')
                     for op in entry['insn'].ops)]
    if len(stars) != 1:
        result = {'error': 'model-name check is absent or ambiguous', 'count': len(stars)}
    else:
        timedemo = [(entry, next(iter(entry['targets'])))
                    for i, entry in enumerate(wrapper_entries[:stars[0]])
                    if len(entry['targets']) == 1 and entry['disp']
                    and is_zero_checked(i, wrapper_entries)
                    and is_writable_data(next(iter(entry['targets'])))]
        moving_entries = [entry for entry in core_entries if moving in entry['targets'] and entry['disp']]
        onground_entries = [entry for entry in core_entries if onground in entry['targets'] and entry['disp']]
        if len(timedemo) != 1 or len(moving_entries) != 1 or len(onground_entries) != 1:
            result = {'error': 'field accesses are absent or ambiguous',
                      'timedemo': len(timedemo), 'moving': len(moving_entries),
                      'onground': len(onground_entries)}
        elif not (moving_entries[0]['ea'] < onground_entries[0]['ea']
                  and is_zero_checked(core_entries.index(moving_entries[0]), core_entries)):
            result = {'error': 'moving/onground guard does not match source control flow'}
        else:
            result = {
                'timedemo': access(timedemo[0][0], timedemo[0][1]),
                'moving': access(moving_entries[0], moving),
                'onground': access(onground_entries[0], onground),
            }
"""


async def _validated_waterlevel(session, new_binary_dir, platform, image_base):
    artifact = u._load_yaml_mapping(Path(new_binary_dir) / f"{WATERLEVEL}.{platform}.yaml")
    if not artifact or artifact.get("gv_name") != WATERLEVEL:
        return None
    try:
        ea = int(artifact["gv_va"], 0)
        signature_ea = int(artifact["gv_sig_va"], 0)
        instruction_ea = signature_ea + int(artifact["gv_inst_offset"], 0)
        displacement = int(artifact["gv_inst_disp"], 0)
        signature = artifact["gv_sig"]
    except (KeyError, TypeError, ValueError):
        return None
    if ea < int(image_base) or await u._find_unique_bytes(session, signature) != signature_ea:
        return None
    checked = await u.gv_resolution_fields_via_mcp(session, instruction_ea, displacement, ea, image_base, platform)
    return ea if checked is not None else None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if any(u._output_for_symbol(expected_outputs, name) is None for name in (TIMEDEMO, MOVING, ONGROUND)):
        return False
    waterlevel = await _validated_waterlevel(session, new_binary_dir, platform, image_base)
    if waterlevel is None:
        if debug:
            print("  interpolation globals: cl_waterlevel artifact is unavailable or invalid")
        return False
    wrapper = await inspect_owner_artifact(
        session,
        new_binary_dir,
        platform,
        image_base,
        INTERPOLATOR,
        func_name=function_identity(new_binary_dir, platform, INTERPOLATOR),
    )
    if wrapper is None:
        return False
    is_hl8684_linux = platform == "linux" and Path(new_binary_dir).parent.name == "hl-8684"
    core = (
        await inspect_owner_artifact(session, new_binary_dir, platform, image_base, SPLIT_CORE)
        if is_hl8684_linux
        else wrapper
    )
    if core is None:
        return False
    found = await run_walk(
        session,
        WALK,
        {
            "wrapper": hex(wrapper["owner_ea"]),
            "core": hex(core["owner_ea"]),
            "waterlevel": hex(waterlevel),
        },
    )
    if not isinstance(found, dict) or found.get("error"):
        if debug:
            print(f"  interpolation globals: locator failed {found}")
        return False
    selected = {TIMEDEMO: found["timedemo"], MOVING: found["moving"], ONGROUND: found["onground"]}
    if is_hl8684_linux:
        if not await write_located_globals(
            session, expected_outputs, platform, image_base, wrapper, {TIMEDEMO: selected[TIMEDEMO]}
        ):
            return False
        return await write_located_globals(
            session,
            expected_outputs,
            platform,
            image_base,
            core,
            {MOVING: selected[MOVING], ONGROUND: selected[ONGROUND]},
        )
    return await write_located_globals(session, expected_outputs, platform, image_base, wrapper, selected)
