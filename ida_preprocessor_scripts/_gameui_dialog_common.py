"""Prepare GameUI's exact C-string anchors for the shared xref finder."""

from ida_analyze_util import DEFAULT_IDA_STRING_MIN_LENGTH, parse_mcp_result


async def prepare_c_strings(session):
    # Some analyzed ELF databases omit valid, referenced literals from IDA's
    # current string list. Rebuild that list before using FULLMATCH xrefs.
    code = f"""
import idautils, ida_nalt, json
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen={DEFAULT_IDA_STRING_MIN_LENGTH})
result = json.dumps({{'ok': True}})
"""
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:
        return False
    return isinstance(payload, dict) and payload.get("ok") is True
