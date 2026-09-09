#!/usr/bin/env python3
"""Locate heap-limit MOV/CMP immediates inside Sys_InitMemory.

MetaHook HeapPatch rewrites those immediates at runtime (WriteDWORD at the
imm offset it re-derives from the instruction), raising the engine heap cap.
Each qualifying instruction is a separate patch artifact:

    Sys_InitMemory_HeapLimitPatches_0
    Sys_InitMemory_HeapLimitPatches_1
    ...

Numbering is the Sys_InitMemory-body instruction address order, starting at 0.

patch_va / patch_rva are the unique patch_sig match start: the instruction
that owns the immediate, never the imm's own four bytes. patch_sig_disp is the
byte displacement from that match to the instruction, always 0 here because the
signature starts at the instruction. patch_bytes is omitted: the consumer
decodes the instruction again to find its imm offset before writing.

Heap-limit immediates (D:\\MetaHookSv\\Plugins\\HeapPatch\\privatehook.cpp
IsHeapLimitImmediate): SvEngine gates on 512MB, every other engine on
32/40/128MB. The union set is used uniformly because the inspected
Sys_InitMemory bodies never contain the other family's immediates:
svencoop-10257 Windows/Linux only carry 512MB sites, hl-*/cof-* only
32/40/128MB sites (blob 3248-4554: 32+40MB; 6153+/HL25/CoF: 40+128MB).
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

PATCH_NAME_PREFIX = "Sys_InitMemory_HeapLimitPatches_"
OWNER_FUNC_NAME = "Sys_InitMemory"
HEAP_LIMIT_IMMEDIATES = (0x2000000, 0x2800000, 0x8000000, 0x20000000)

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
import json
import traceback

SYS_INITMEMORY_EA = SYS_INITMEMORY_EA_PLACEHOLDER
HEAP_LIMIT_IMMEDIATES = HEAP_LIMIT_IMMEDIATES_PLACEHOLDER
MIN_SIG_BYTES = 6
MAX_SIG_BYTES = 96
MAX_INSTRUCTIONS = 64

def raw_bin_search(ea, max_ea, data, data_mask, flags=0):
    if hasattr(ida_bytes, 'find_bytes'):
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=data_mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, data_mask, len(data), flags)

def database_limits():
    if hasattr(idaapi, 'inf_get_min_ea') and hasattr(idaapi, 'inf_get_max_ea'):
        return int(idaapi.inf_get_min_ea()), int(idaapi.inf_get_max_ea())
    inf = getattr(getattr(idaapi, 'cvar', None), 'inf', None)
    if inf is not None:
        return int(inf.min_ea), int(inf.max_ea)
    return 0, 0xFFFFFFFF

def exec_ranges():
    ranges = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(int(start))
        if seg is None:
            continue
        perms = int(getattr(seg, 'perm', 0))
        executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
        if perms & executable:
            ranges.append((int(seg.start_ea), int(seg.end_ea)))
    if ranges:
        return ranges
    return [database_limits()]

def count_matches(tokens, expected_addr):
    if not tokens or all(token == '??' for token in tokens):
        return 0
    data = bytes(0 if token == '??' else int(token, 16) for token in tokens)
    mask = bytes(0x00 if token == '??' else 0xFF for token in tokens)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
    matches = []
    for start, end in exec_ranges():
        ea = raw_bin_search(start, end, data, mask, flags)
        while ea != idaapi.BADADDR and len(matches) < 3:
            matches.append(int(ea))
            ea = raw_bin_search(int(ea) + 1, end, data, mask, flags)
        if len(matches) >= 3:
            break
    unique = sorted(set(matches))
    if expected_addr is not None and unique == [int(expected_addr)]:
        return 1
    return len(unique)

def wildcard_instruction(insn, raw_bytes):
    wild = set()
    for op in insn.ops:
        ot = int(op.type)
        if ot == int(idaapi.o_void):
            continue
        if ot in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
            offb = int(getattr(op, 'offb', 0))
            if offb > 0 and offb < insn.size:
                dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                if dsz <= 0:
                    dsz = insn.size - offb
                for index in range(offb, min(insn.size, offb + dsz)):
                    wild.add(index)
    b0 = raw_bytes[0]
    if b0 in (0xE8, 0xE9, 0xEB):
        for index in range(1, insn.size):
            wild.add(index)
    elif b0 == 0x0F and insn.size >= 2 and (raw_bytes[1] & 0xF0) == 0x80:
        for index in range(2, insn.size):
            wild.add(index)
    elif 0x70 <= b0 <= 0x7F:
        for index in range(1, insn.size):
            wild.add(index)
    return ['??' if index in wild else '%02X' % raw_bytes[index] for index in range(insn.size)]

def generate_patch_sig(target_inst):
    insn0 = idautils.DecodeInstruction(int(target_inst))
    if not insn0 or insn0.size <= 0:
        return None, 'failed to decode target instruction'
    raw0 = ida_bytes.get_bytes(int(target_inst), insn0.size)
    if not raw0:
        return None, 'failed to read target instruction bytes'
    search_end = database_limits()[1]
    limit_end = int(target_inst) + MAX_SIG_BYTES
    fwd_tokens = []
    fwd_boundaries = []
    cursor = int(target_inst)
    inst_count = 0
    target_inst_len = None
    while (
        cursor < search_end
        and cursor < limit_end
        and len(fwd_tokens) < MAX_SIG_BYTES
        and inst_count < MAX_INSTRUCTIONS
    ):
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break
        if cursor == int(target_inst):
            target_inst_len = insn.size
            for idx in range(insn.size):
                if len(fwd_tokens) < MAX_SIG_BYTES:
                    fwd_tokens.append('%02X' % raw[idx])
        else:
            for token in wildcard_instruction(insn, raw):
                if len(fwd_tokens) < MAX_SIG_BYTES:
                    fwd_tokens.append(token)
        fwd_boundaries.append(len(fwd_tokens))
        cursor += insn.size
        inst_count += 1
    if target_inst_len is None:
        return None, 'no signature bytes collected'
    min_boundary = max(MIN_SIG_BYTES, target_inst_len)
    for boundary in fwd_boundaries:
        if boundary < min_boundary:
            continue
        prefix = fwd_tokens[:boundary]
        if count_matches(prefix, target_inst) == 1:
            return {
                'patch_sig': ' '.join(prefix),
                'patch_sig_disp': 0,
                'patch_inst_length': target_inst_len,
                'original_bytes': ' '.join('%02X' % byte for byte in raw0),
            }, None
    return None, 'no unique signature found with forward-only expansion'

def is_heap_limit_instruction(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size <= 0:
        return False, None
    mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
    if mnem not in ('mov', 'cmp'):
        return False, None
    used = [op for op in insn.ops if int(op.type) != int(idaapi.o_void)]
    if len(used) != 2:
        return False, None
    if int(used[1].type) != int(idaapi.o_imm):
        return False, None
    imm = int(used[1].value) & 0xFFFFFFFF
    if imm not in HEAP_LIMIT_IMMEDIATES:
        return False, None
    return True, imm

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(SYS_INITMEMORY_EA))
    if owner is None or int(owner.start_ea) != int(SYS_INITMEMORY_EA):
        raise RuntimeError('Sys_InitMemory is not a function start')
    sites = []
    errors = []
    for ea in idautils.FuncItems(int(owner.start_ea)):
        if int(ea) < int(owner.start_ea) or int(ea) >= int(owner.end_ea):
            continue
        matches, imm = is_heap_limit_instruction(ea)
        if not matches:
            continue
        generated, error = generate_patch_sig(ea)
        insn = idautils.DecodeInstruction(int(ea))
        rec = {
            'ea': hex(int(ea)),
            'mnem': (idc.print_insn_mnem(int(ea)) or '').lower(),
            'disasm': idc.generate_disasm_line(int(ea), 0) or '',
            'insn_len': int(insn.size) if insn else None,
            'imm': hex(int(imm)),
        }
        if generated is None:
            rec['error'] = error
            errors.append(rec)
        else:
            rec.update(generated)
            sites.append(rec)
    if errors:
        result = json.dumps({
            'error': 'failed to generate a unique patch signature',
            'sys_initmemory': hex(int(owner.start_ea)),
            'sites': sites,
            'errors': errors,
        })
    else:
        result = json.dumps({
            'pointer_size': 4,
            'sys_initmemory': hex(int(owner.start_ea)),
            'sys_initmemory_end': hex(int(owner.end_ea)),
            'sites': sites,
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


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


def _expected_patch_outputs(expected_outputs):
    indexed = {}
    for value in expected_outputs or ():
        path = Path(value)
        stem = path.name
        for suffix in (".windows.yaml", ".linux.yaml", ".yaml"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        if not stem.startswith(PATCH_NAME_PREFIX):
            continue
        suffix = stem[len(PATCH_NAME_PREFIX) :]
        if not suffix.isdigit():
            return None
        index = int(suffix)
        if index in indexed:
            return None
        indexed[index] = (stem, path)
    if not indexed:
        return None
    expected_indexes = sorted(indexed)
    if expected_indexes != list(range(len(expected_indexes))):
        return None
    return [indexed[index] for index in expected_indexes]


async def _locate_patches(session, sys_initmemory_ea):
    immediates = "[" + ", ".join(hex(value) for value in HEAP_LIMIT_IMMEDIATES) + "]"
    code = LOCATE_PY.replace("SYS_INITMEMORY_EA_PLACEHOLDER", str(int(sys_initmemory_ea))).replace(
        "HEAP_LIMIT_IMMEDIATES_PLACEHOLDER", immediates
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
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    expected = _expected_patch_outputs(expected_outputs)
    if expected is None:
        if debug:
            print("  find-Sys_InitMemory_HeapLimitPatches: expected outputs are not contiguous patch indexes")
        return False
    owner_artifact = _function_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner_artifact is None:
        if debug:
            print("  find-Sys_InitMemory_HeapLimitPatches: missing Sys_InitMemory artifact")
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
            print("  find-Sys_InitMemory_HeapLimitPatches: failed to verify Sys_InitMemory artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_patches(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-Sys_InitMemory_HeapLimitPatches: locator failed {located}")
        return False
    sites = located.get("sites")
    if not isinstance(sites, list) or not sites:
        return False
    if len(sites) != len(expected):
        if debug:
            print(
                "  find-Sys_InitMemory_HeapLimitPatches: "
                f"found {len(sites)} heap-limit immediates, expected {len(expected)}: {sites}"
            )
        return False
    try:
        owner_end = int(located["sys_initmemory_end"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    for index, (patch_name, output) in enumerate(expected):
        site = sites[index]
        if not isinstance(site, dict):
            return False
        if _output_for_symbol([output], patch_name) is None:
            return False
        try:
            patch_ea = int(site["ea"], 0)
            imm = int(site["imm"], 0)
            patch_sig_disp = int(site["patch_sig_disp"])
            insn_len = int(site["insn_len"])
        except (TypeError, ValueError, KeyError):
            return False
        patch_sig = site.get("patch_sig")
        if not isinstance(patch_sig, str) or not patch_sig.strip():
            return False
        if imm not in HEAP_LIMIT_IMMEDIATES:
            return False
        if patch_ea < owner_ea or patch_ea >= owner_end or patch_sig_disp != 0 or insn_len <= 0:
            return False
        unique_ea = await _find_unique_bytes(session, patch_sig)
        if unique_ea != patch_ea:
            if debug:
                print(
                    "  find-Sys_InitMemory_HeapLimitPatches: "
                    f"{patch_name} signature is not unique at {site.get('ea')}: {unique_ea}"
                )
            return False
        if debug:
            print(f"  find-Sys_InitMemory_HeapLimitPatches: {patch_name} ea={site['ea']} {site.get('disasm', '')}")
        write_patch_yaml(
            output,
            {
                "patch_name": patch_name,
                "patch_va": hex(patch_ea),
                "patch_rva": hex(patch_ea - int(image_base)),
                "patch_sig": patch_sig,
                "patch_sig_disp": patch_sig_disp,
            },
        )
    return True
