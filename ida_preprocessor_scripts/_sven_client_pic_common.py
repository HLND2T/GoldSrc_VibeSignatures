"""Shared SvEngine-Linux PIC string-owner recovery for the client module.

GCC PIC builds reference .rodata literals through ``lea reg, [gotreg+disp32]``
where the embedded dword is ``literal - _GLOBAL_OFFSET_TABLE_``. IDA creates
no xref for those sites, so a FULLMATCH string with exactly one such owner
still reports zero owners through the shared string machinery (validated on
svencoop-10257 client.so: the portal diagnostics are reachable only this way,
while e.g. the invisible-texture literal also keeps a resolvable reference).

The locator keeps the exact string literal as the only semantic anchor: it
resolves the module GOT anchor from the standard
``call __x86.get_pc_thunk.reg; add reg, imm32`` prologue, derives the unique
4-byte GOTOFF displacement of the literal, finds the displacement sites and
accepts them only inside decoded disp32 operands. Owners = the containing
functions; exactly one owner must remain.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

PIC_STRING_OWNERS_PY = r"""
def main(values):
    import ida_bytes, ida_funcs, ida_segment, ida_ua, idaapi, idautils, idc, json, struct
    target = int(values['string_ea'])
    owners = set()
    for xref in idautils.XrefsTo(target, 0):
        fn = ida_funcs.get_func(int(xref.frm))
        if fn is not None:
            owners.add(int(fn.start_ea))
    if len(owners) == 1:
        return {'pointer_size': 4, 'owners': [hex(ea) for ea in sorted(owners)], 'via': 'xref'}

    # Resolve the module GOT anchor from any thunk+add prologue.
    got_base = None
    for fea in idautils.Functions():
        fn = ida_funcs.get_func(fea)
        if fn is None:
            continue
        items = list(idautils.FuncItems(fea))[:8]
        for idx, cur in enumerate(items):
            if (idc.print_insn_mnem(cur) or '').lower() != 'call':
                continue
            nxt = items[idx + 1] if idx + 1 < len(items) else None
            if nxt is None or (idc.print_insn_mnem(nxt) or '').lower() != 'add':
                continue
            if idc.get_operand_type(nxt, 1) != 5:
                continue
            callee = idc.get_operand_value(cur, 0)
            callee_fn = ida_funcs.get_func(callee) if callee else None
            if callee_fn is None or int(callee_fn.end_ea) - int(callee_fn.start_ea) > 4:
                continue
            got_base = (int(nxt) + int(idc.get_operand_value(nxt, 1))) & 0xFFFFFFFF
            break
        if got_base is not None:
            break
    if got_base is None:
        return {'error': 'no GOT anchor in module'}

    disp = (target - got_base) & 0xFFFFFFFF
    needle = ' '.join('%02X' % b for b in struct.pack('<I', disp))
    for segment_index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(segment_index)
        if segment is None or not (int(segment.perm) & 1):
            continue
        cursor = int(segment.start_ea)
        while cursor < int(segment.end_ea):
            hit = ida_bytes.find_bytes(
                needle, cursor, range_end=int(segment.end_ea),
                flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
            if hit is None or hit == idaapi.BADADDR or int(hit) >= int(segment.end_ea):
                break
            cursor = int(hit) + 1
            head = int(idc.get_item_head(int(hit)))
            if head == int(hit) or not idc.is_code(idc.get_full_flags(head)):
                continue
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, head):
                continue
            matched = False
            for op in insn.ops:
                if int(op.type) == 0:
                    break
                offb = int(getattr(op, 'offb', 0) or 0)
                if int(op.type) == 4 and offb and head + offb == int(hit):
                    matched = True
                    break
            if not matched:
                continue
            fn = ida_funcs.get_func(head)
            if fn is not None and int(fn.start_ea) <= head < int(fn.end_ea):
                owners.add(int(fn.start_ea))
    return {'pointer_size': 4, 'owners': [hex(ea) for ea in sorted(owners)], 'via': 'gotoff'}
import json
result = json.dumps(main(VALUES))
"""


async def string_owner_ea(session, string_ea, label="string owner", debug=False):
    """Return the unique function owner of the exact string address, else None.

    Prefers the direct xref owners; falls back to the GOTOFF displacement scan
    when IDA created no reference. Zero or multiple owners fail closed.
    """
    import json

    values = json.dumps({"string_ea": int(string_ea)})
    try:
        payload = parse_mcp_result(
            await session.call_tool("py_eval", {"code": PIC_STRING_OWNERS_PY.replace("VALUES", values)})
        )
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict) or payload.get("error") or payload.get("pointer_size") != 4:
        if debug:
            print(f"  {label}: PIC string owner scan failed {payload}")
        return None
    owners = payload.get("owners") or []
    if len(owners) != 1:
        if debug:
            print(f"  {label}: PIC string owners {owners} via {payload.get('via')}")
        return None
    try:
        return int(owners[0], 0)
    except (TypeError, ValueError):
        return None


async def unique_string_owner_ea(session, literal, label="string owner", debug=False):
    """Return the unique function owner of the exact literal, else None."""
    string_ea = await exact_string_ea(session, literal)
    if string_ea is None:
        if debug:
            print(f"  {label}: no unique exact string instance")
        return None
    return await string_owner_ea(session, string_ea, label=label, debug=debug)


async def write_unique_string_owner_artifact(
    session,
    expected_outputs,
    func_name,
    string_ea,
    image_base,
    debug=False,
):
    """Emit ``func_name`` from the unique owner of the exact string address."""
    owner_ea = await string_owner_ea(session, string_ea, label=func_name, debug=debug)
    if owner_ea is None:
        return False
    output = _output_for_symbol(expected_outputs, func_name)
    if output is None:
        return False
    function = await _inspect_function_via_mcp(session, owner_ea, image_base, func_name)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session, owner_ea, image_base, func_name, allow_across_function_boundary=True
        )
    if not function:
        return False
    artifact = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        artifact["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, artifact)
    return True


EXACT_STRING_EA_PY = r"""
def main(values):
    import ida_nalt, idautils, json
    matches = []
    for item in idautils.Strings(default_setup=False):
        pass
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    for item in strings:
        if str(item) == values['literal']:
            matches.append(hex(int(item.ea)))
    return {'pointer_size': 4, 'matches': matches}
import json
result = json.dumps(main(VALUES))
"""


async def exact_string_ea(session, literal):
    """Return the unique exact-match string item address, else None."""
    import json

    values = json.dumps({"literal": literal})
    try:
        payload = parse_mcp_result(
            await session.call_tool("py_eval", {"code": EXACT_STRING_EA_PY.replace("VALUES", values)})
        )
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict) or payload.get("pointer_size") != 4:
        return None
    matches = payload.get("matches") or []
    if len(matches) != 1:
        return None
    try:
        return int(matches[0], 0)
    except (TypeError, ValueError):
        return None


async def preprocess_string_owner_skill_with_pic_fallback(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    func_name,
    literal,
    debug=False,
):
    """Standard string-xref discovery with the SvEngine PIC owner fallback."""
    from ida_analyze_util import preprocess_common_skill

    func_xrefs = [
        {
            "func_name": func_name,
            "xref_strings": [f"FULLMATCH:{literal}"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        }
    ]
    if await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[func_name],
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=[(func_name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])],
        debug=debug,
    ):
        return True
    string_ea = await exact_string_ea(session, literal)
    if string_ea is None:
        return False
    return await write_unique_string_owner_artifact(
        session, expected_outputs, func_name, string_ea, image_base, debug=debug
    )
