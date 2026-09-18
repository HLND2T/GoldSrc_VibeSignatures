#!/usr/bin/env python3
"""Shared CGame_AppActivate discovery and session-local boundary recovery.

engine/sys_sdlwind.cpp and engine/sys_mainwind.cpp implement
``CGame::AppActivate(bool fActive)``; each branch announces itself with
``AppActive: active`` or ``AppActive: not active`` before guarding the rest of
the body with ``host_initialized``. The legacy ``AppActivate(BOOL, BOOL)`` in
engine/vid_win.c and engine/gl_vidnt.c prints neither literal, so the pair
belongs to the CGame method alone and both literals are owned by the target
itself.

Two build-specific shapes prevent a plain string-xref locator from naming the
entry, so discovery resolves the anchor's own control-flow root instead of
trusting IDA's containing function:

* The decrypted blob engines and hl-4554 merge the whole CGame static
  constructor/destructor cluster into one oversized function whose start is an
  ``atexit`` thunk. The real method begins at the anchor component's root,
  which is reached by a direct call from outside that component.
* hl-8684 Linux keeps both ``CGame::AppActivate(bool)`` and a GCC
  ``.constprop`` clone that takes its argument in a register. Only the base
  symbol has the declared ABI, so a clone never outranks it.

Generated signatures validate the located output but never participate in
discovery.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact

TARGET_FUNCTION = "CGame_AppActivate"
ANCHOR_STRINGS = ("AppActive: active\n", "AppActive: not active\n")

LOCATE_PY = r"""
import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

ANCHOR_STRINGS = ANCHOR_STRINGS_PLACEHOLDER
EXPECTED_ENTRY = EXPECTED_ENTRY_PLACEHOLDER
CLONE_SUFFIXES = ('.constprop', '.part', '.isra', '.cold', '.localalias')
MAX_SPLIT_SPAN = 0x4000


def is_executable(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None:
        return False
    return bool(int(getattr(seg, 'perm', 0)) & int(getattr(ida_segment, 'SEGPERM_EXEC', 1)))


def same_executable_segment(start, end):
    first = ida_segment.getseg(int(start))
    last = ida_segment.getseg(max(int(start), int(end) - 1))
    if first is None or last is None:
        return False
    return int(first.start_ea) == int(last.start_ea) and is_executable(int(start))


def exact_string_addresses(text):
    found = []
    for item in idautils.Strings():
        if str(item) == text:
            found.append(int(item.ea))
    return found


def operand_sites(address):
    sites = set()
    for start in idautils.Functions():
        for ea in idautils.FuncItems(int(start)):
            insn = idautils.DecodeInstruction(int(ea))
            if not insn:
                continue
            for op in insn.ops:
                if int(op.type) == int(idaapi.o_void):
                    break
                value = None
                if int(op.type) == int(idaapi.o_imm):
                    value = int(op.value) & 0xFFFFFFFF
                elif int(op.type) == int(idaapi.o_mem):
                    value = int(op.addr) & 0xFFFFFFFF
                if value == int(address):
                    sites.add(int(ea))
    return sites


def reference_sites(address):
    sites = set()
    for xref in idautils.XrefsTo(int(address), 0):
        source = int(xref.frm)
        if is_executable(source):
            sites.add(source)
    # Several early PE databases retain the encoded operand without its xref.
    return sites or operand_sites(address)


def block_map(func):
    blocks = {}
    for block in idaapi.FlowChart(func):
        preds = []
        for pred in block.preds():
            preds.append(int(pred.start_ea))
        succs = []
        for succ in block.succs():
            succs.append(int(succ.start_ea))
        blocks[int(block.start_ea)] = {
            'start': int(block.start_ea),
            'end': int(block.end_ea),
            'preds': preds,
            'succs': succs,
        }
    return blocks


def containing_block(blocks, ea):
    for start in blocks:
        if blocks[start]['start'] <= int(ea) < blocks[start]['end']:
            return start
    return None


def closure(blocks, seeds, key):
    seen = set()
    pending = []
    for seed in seeds:
        pending.append(int(seed))
    while pending:
        current = pending.pop()
        if current in seen or current not in blocks:
            continue
        seen.add(current)
        for neighbour in blocks[current][key]:
            pending.append(int(neighbour))
    return seen


def component_roots(blocks, anchor):
    seed = containing_block(blocks, anchor)
    if seed is None:
        return []
    roots = []
    for start in closure(blocks, [seed], 'preds'):
        if not blocks[start]['preds']:
            roots.append(start)
    roots.sort()
    return roots


def component_span(blocks, root):
    forward = closure(blocks, [root], 'succs')
    ranges = []
    for start in forward:
        ranges.append((blocks[start]['start'], blocks[start]['end']))
    ranges.sort()
    if not ranges:
        return None
    span_end = ranges[0][1]
    cursor = ranges[0][1]
    for start, end in ranges[1:]:
        if start != cursor:
            return None
        cursor = end
        span_end = end
    return {'start': ranges[0][0], 'end': span_end, 'blocks': forward}


def direct_call_sources(entry):
    sources = []
    for xref in idautils.XrefsTo(int(entry), 0):
        source = int(xref.frm)
        if not is_executable(source):
            continue
        if (idc.print_insn_mnem(source) or '').lower() != 'call':
            continue
        sources.append(source)
    return sources


def clone_base_name(name):
    text = str(name or '')
    for suffix in CLONE_SUFFIXES:
        index = text.find(suffix)
        if index > 0:
            return text[:index], True
    return text, False


def restore_merged_owner(owner_start, owner_end, entry, original_chunks):
    # Only functions created in the released main-chunk range may be removed.
    # Existing constructor tails outside that range must remain attached.
    try:
        created = sorted(set(
            int(start) for start in idautils.Functions(entry, owner_end)
            if entry <= int(start) < owner_end
        ))
        for start in created:
            for chunk_start, chunk_end in idautils.Chunks(start):
                if not (entry <= int(chunk_start) < int(chunk_end) <= owner_end):
                    return 'new function extends outside the original owner'
        for start in created:
            if not ida_funcs.del_func(start):
                return 'failed to remove newly created function %s' % hex(start)
        if not ida_funcs.set_func_end(owner_start, owner_end):
            return 'failed to restore the original owner end'
        restored = ida_funcs.get_func(owner_start)
        if restored is None or int(restored.start_ea) != owner_start or int(restored.end_ea) != owner_end:
            return 'original owner boundaries were not restored'
        chunks = [(int(start), int(end)) for start, end in idautils.Chunks(owner_start)]
        if chunks != original_chunks:
            return 'original owner chunks were not restored'
        return None
    except Exception as exc:
        return str(exc)


def split_merged_function(owner, entry, span):
    # The blob engines merge the CGame constructor cluster with the method.
    # Truncate that merged function at the real entry, define the method, then
    # let auto-analysis rebuild whatever followed it.
    owner_start = int(owner.start_ea)
    owner_end = int(owner.end_ea)
    if int(span['start']) != int(entry) or int(span['end']) <= int(entry):
        return 'component span does not start at the recovered entry'
    if not (owner_start < int(entry) < owner_end) or int(span['end']) > owner_end:
        return 'entry is not interior to its merged owner'
    original_chunks = [(int(start), int(end)) for start, end in idautils.Chunks(owner_start)]
    if int(span['end']) - int(entry) > MAX_SPLIT_SPAN:
        return 'component span is too large to split'
    if not same_executable_segment(int(entry), int(span['end'])):
        return 'component span crosses an executable segment boundary'
    outside = []
    for source in direct_call_sources(int(entry)):
        if not (int(entry) <= source < int(span['end'])):
            outside.append(source)
    if not outside:
        return 'no direct call reaches the recovered entry from outside it'
    try:
        if not ida_funcs.set_func_end(owner_start, int(entry)):
            raise RuntimeError('failed to truncate the merged owner')
        if not ida_funcs.add_func(int(entry), int(span['end'])):
            raise RuntimeError('failed to define the recovered entry')
        if int(span['end']) < owner_end:
            ida_auto.plan_range(int(span['end']), owner_end)
            if not ida_auto.auto_wait():
                raise RuntimeError('auto-analysis did not complete')
        recovered = ida_funcs.get_func(int(entry))
        if recovered is None or int(recovered.start_ea) != int(entry) or int(recovered.end_ea) != int(span['end']):
            raise RuntimeError('recovered entry did not become a function start')
    except Exception as exc:
        rollback_error = restore_merged_owner(owner_start, owner_end, int(entry), original_chunks)
        if rollback_error is not None:
            return '%s; rollback failed: %s' % (exc, rollback_error)
        return str(exc)
    return None


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')

    anchors = []
    string_report = {}
    for text in ANCHOR_STRINGS:
        addresses = exact_string_addresses(text)
        if len(addresses) != 1:
            raise RuntimeError('anchor %r occurs %d times, expected 1' % (text, len(addresses)))
        sites = sorted(reference_sites(addresses[0]))
        if not sites:
            raise RuntimeError('anchor %r has no code reference' % (text,))
        string_report[text] = {'address': hex(addresses[0]), 'sites': [hex(site) for site in sites]}
        anchors.extend(sites)
    anchors = sorted(set(anchors))

    owners = {}
    for anchor in anchors:
        func = ida_funcs.get_func(int(anchor))
        if func is None:
            raise RuntimeError('anchor %s has no containing function' % hex(anchor))
        owners.setdefault(int(func.start_ea), []).append(int(anchor))

    entries = {}
    for owner_start in sorted(owners):
        owner = ida_funcs.get_func(int(owner_start))
        blocks = block_map(owner)
        roots = set()
        for anchor in owners[owner_start]:
            anchor_roots = component_roots(blocks, anchor)
            if len(anchor_roots) != 1:
                raise RuntimeError(
                    'anchor %s resolves to %d control-flow roots' % (hex(anchor), len(anchor_roots))
                )
            roots.add(anchor_roots[0])
        if len(roots) != 1:
            raise RuntimeError('owner %s exposes %d anchor roots' % (hex(owner_start), len(roots)))
        root = next(iter(roots))
        span = component_span(blocks, root)
        if span is None:
            if root != int(owner.start_ea):
                raise RuntimeError('merged entry %s has a noncontiguous component span' % hex(root))
            span = {'start': root, 'end': int(owner.end_ea), 'blocks': set()}
        entries[root] = {
            'owner_start': int(owner.start_ea),
            'owner_end': int(owner.end_ea),
            'span_start': int(span['start']),
            'span_end': int(span['end']),
            'anchors': sorted(owners[owner_start]),
            'name': ida_name.get_name(int(root)) or '',
        }

    candidates = sorted(entries)
    clone_report = {}
    if len(candidates) > 1:
        # GCC clones such as ``.constprop.N`` take their arguments in
        # registers; only the base symbol keeps the declared ABI.
        bases = []
        for entry in candidates:
            base, is_clone = clone_base_name(entries[entry]['name'])
            clone_report[hex(entry)] = {'name': entries[entry]['name'], 'base': base, 'is_clone': is_clone}
            if not is_clone:
                bases.append((entry, base))
        if len(bases) == 1:
            base_entry, base_name = bases[0]
            others = []
            for entry in candidates:
                if entry == base_entry:
                    continue
                candidate_base, is_clone = clone_base_name(entries[entry]['name'])
                if is_clone and candidate_base == base_name and base_name:
                    others.append(entry)
            if len(others) == len(candidates) - 1:
                candidates = [base_entry]

    if len(candidates) != 1:
        raise RuntimeError('CGame_AppActivate candidate count is %d, expected 1' % len(candidates))

    entry = candidates[0]
    if EXPECTED_ENTRY is not None and int(entry) != int(EXPECTED_ENTRY):
        raise RuntimeError('located entry does not match the CGame_AppActivate artifact')
    info = entries[entry]
    split_reason = None
    if entry != info['owner_start']:
        owner = ida_funcs.get_func(int(info['owner_start']))
        split_reason = split_merged_function(
            owner,
            int(entry),
            {'start': int(info['span_start']), 'end': int(info['span_end'])},
        )
        if split_reason is not None:
            raise RuntimeError('cannot recover the merged entry: %s' % split_reason)

    final = ida_funcs.get_func(int(entry))
    if final is None or int(final.start_ea) != int(entry):
        raise RuntimeError('recovered entry %s is not a function start' % hex(entry))

    result = json.dumps({
        'pointer_size': 4,
        'func_va': hex(int(entry)),
        'func_size': hex(int(final.end_ea) - int(final.start_ea)),
        'func_name': ida_name.get_name(int(entry)) or '',
        'strings': string_report,
        'merged_owner': None if entry == info['owner_start'] else hex(int(info['owner_start'])),
        'clone_report': clone_report,
        'entry_bytes': (ida_bytes.get_bytes(int(entry), 12) or b'').hex(),
    })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _parse_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


async def locate_cgame_appactivate(session, image_base, *, expected_entry=None, debug=False):
    """Locate and recover the method in this session, without writing artifacts."""
    code = LOCATE_PY.replace("ANCHOR_STRINGS_PLACEHOLDER", repr(ANCHOR_STRINGS)).replace(
        "EXPECTED_ENTRY_PLACEHOLDER", repr(expected_entry)
    )
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {TARGET_FUNCTION}: locator failed {located}")
        return None
    try:
        func_va = _parse_int(located["func_va"])
    except (KeyError, TypeError, ValueError):
        return None
    if func_va < int(image_base) or (expected_entry is not None and func_va != expected_entry):
        return None
    return located


async def inspect_cgame_appactivate_artifact(session, new_binary_dir, platform, image_base, *, debug=False):
    """Recover session-local boundaries when an upstream artifact was reused."""
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{TARGET_FUNCTION}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != TARGET_FUNCTION:
        return None
    try:
        expected_entry = _parse_int(artifact["func_va"])
    except (KeyError, TypeError, ValueError):
        return None
    if expected_entry < int(image_base):
        return None
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, TARGET_FUNCTION)
    if owner is not None:
        return owner
    located = await locate_cgame_appactivate(session, image_base, expected_entry=expected_entry, debug=debug)
    if located is None:
        return None
    return await inspect_owner_artifact(session, new_binary_dir, platform, image_base, TARGET_FUNCTION)


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
    del old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNCTION)
    if output is None:
        if debug:
            print(f"  {skill_name}: missing the {TARGET_FUNCTION} output")
        return False

    located = await locate_cgame_appactivate(session, image_base, debug=debug)
    if located is None:
        return False
    func_va = _parse_int(located["func_va"])

    function = await _inspect_function_via_mcp(session, func_va, image_base, TARGET_FUNCTION)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session,
            func_va,
            image_base,
            TARGET_FUNCTION,
            allow_across_function_boundary=True,
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {skill_name}: failed to inspect {hex(func_va)}")
        return False
    try:
        if _parse_int(function["func_va"]) != func_va:
            return False
    except (KeyError, TypeError, ValueError):
        return False

    payload = {
        "func_name": TARGET_FUNCTION,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    if debug:
        print(
            f"  {skill_name}: func_va={hex(func_va)} size={function['func_size']} "
            f"merged_owner={located.get('merged_owner')} name={located.get('func_name')!r}"
        )
    write_func_yaml(Path(output), payload)
    return True
