"""Recover the console wrapper when IDA assigns its entry to a caller tail.

SvEngine Windows tail-merges the standalone console wrapper into a caller that
adds developer notification work. IDA records the wrapper at its actual entry
as the caller's sole tail chunk. This helper separates that chunk only after
verifying its sole incoming edge is the caller's direct jump. The analyzer's
owned worker uses the recovered function for artifact validation; its warm IDB
is not saved by the analyzer.
"""

from ida_analyze_util import parse_mcp_result


RECOVER = r"""
import ida_auto, ida_funcs, idaapi, idautils, idc, json

site = SITE_PLACEHOLDER
expected = EXPECTED_PLACEHOLDER
expected_end = EXPECTED_END_PLACEHOLDER
pointer_size = 8 if idaapi.inf_is_64bit() else 4
chunk = ida_funcs.get_fchunk(site)
owner = ida_funcs.get_func(site)
result = {'pointer_size': pointer_size, 'error': 'console wrapper entry is not recoverable'}
if pointer_size == 4 and chunk is not None and owner is not None:
    entry, end = int(chunk.start_ea), int(chunk.end_ea)
    if (expected is None or expected == entry) and (expected_end is None or expected_end == end):
        if int(owner.start_ea) == entry:
            result = {'pointer_size': 4, 'entry': hex(entry), 'end': hex(end), 'split': False}
        elif int(chunk.refqty) == 1:
            incoming = list(idautils.CodeRefsTo(entry, 0))
            if (len(incoming) == 1 and (idc.print_insn_mnem(incoming[0]) or '').lower() == 'jmp'
                    and int(idc.get_operand_value(incoming[0], 0)) == entry
                    and ida_funcs.get_func(incoming[0]) is not None
                    and int(ida_funcs.get_func(incoming[0]).start_ea) == int(owner.start_ea)):
                if ida_funcs.remove_func_tail(owner, entry) and ida_funcs.add_func(entry, end):
                    ida_auto.auto_wait()
                    recovered = ida_funcs.get_func(entry)
                    if (recovered is not None and int(recovered.start_ea) == entry
                            and int(recovered.end_ea) == end):
                        result = {'pointer_size': 4, 'entry': hex(entry),
                                  'end': hex(end), 'split': True}
result = json.dumps(result)
"""


async def recover_console_entry(session, site_ea, *, expected_entry=None, expected_end=None):
    code = (
        RECOVER.replace("SITE_PLACEHOLDER", str(int(site_ea)))
        .replace("EXPECTED_PLACEHOLDER", "None" if expected_entry is None else str(int(expected_entry)))
        .replace("EXPECTED_END_PLACEHOLDER", "None" if expected_end is None else str(int(expected_end)))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("pointer_size") != 4 or "entry" not in payload:
        return None
    try:
        return int(payload["entry"], 0)
    except (TypeError, ValueError):
        return None
