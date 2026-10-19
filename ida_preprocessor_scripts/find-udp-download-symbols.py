#!/usr/bin/env python3
"""Expose the registered dlfile callback and its current client context.

The callback must agree with its own !MD5/custom.hpk branch and the distinct
file/buffer fragment calls. Source assignment, pointer storage and edict
dataflow are cross-checked in the command executor and message dispatcher.
Deterministic current-IDB dataflow is used instead of an LLM/global signature
discovery; all configured PE32, ELF32, BLOB, HL25 and SvEngine inputs are audited.
Runtime signatures are generated only after discovery. GV signatures start at
the decoded access, with the operand wildcarded and PIC resolution preserved.
"""

from ida_analyze_util import (
    _INSPECT_FUNCTION_PY_EVAL,
    _find_unique_bytes,
    _inspect_function_via_mcp,
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    parse_mcp_result,
    write_func_yaml,
    write_gv_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import func_payload, run_walk
from ida_preprocessor_scripts._native_rcon_common import verify_function
from ida_preprocessor_scripts._udp_download_common import WALK
from ida_preprocessor_scripts.renderer_elf_symbols import (
    STT_FUNC,
    current_elf_symbols,
    preserve_global_identities,
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    command = await verify_function(session, new_binary_dir, platform, image_base, "Cmd_ExecuteString")
    if command is None:
        return False
    located = await run_walk(session, WALK, {"command": command["owner_ea"]})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or not located.get("globals"):
        return False
    names = list(located["functions"])
    # These two spellings were read from Sven 8948's actual ELF tables. They
    # are identity checks after discovery, never a way to locate the functions.
    retained = ["_Z22SV_BeginFileDownload_fv", "_Z13SV_DropClientP8client_siPcz"]
    symbols = await current_elf_symbols(session, names + retained) if platform == "linux" else []
    for name, address in located["functions"].items():
        # Select names by their discovered address, never by a guessed mangling.
        identities = {symbol for symbol, value, kind in symbols if kind == STT_FUNC and value == address - image_base}
        if len(identities) > 1:
            return False
        identity = next(iter(identities)) if identities else name
        # Include real body statements beyond the compiler's entry/prologue.
        function = await _inspect_function_via_mcp(session, address, image_base, identity, signature_byte_limit=128)
        output = _output_for_symbol(expected_outputs, name)
        if function is None or output is None:
            return False
        write_func_yaml(output, func_payload(function))
    for name, access in located["globals"].items():
        address, instruction = access["gv_ea"], access["insn_ea"]
        owner = located["owners"][name]
        code = "signature_byte_limit = 128\n" + (
            _INSPECT_FUNCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(owner))
            .replace("IMAGE_BASE_PLACEHOLDER", str(image_base))
            .replace("ALLOW_ACROSS_FUNCTION_BOUNDARY_PLACEHOLDER", "False")
        )
        code += (
            f"\nresult=json.dumps({{'signature': _signature({instruction}, int(func.end_ea)) "
            "if func is not None else None})"
        )
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
        signature = payload.get("signature") if isinstance(payload, dict) else None
        displacement = access["insn_disp"]
        if not signature or signature.split()[displacement : displacement + 4] != ["??"] * 4:
            return False
        if await _find_unique_bytes(session, signature) != instruction:
            return False
        resolution = await gv_resolution_fields_via_mcp(
            session, instruction, displacement, address, image_base, platform
        )
        output = _output_for_symbol(expected_outputs, name)
        if resolution is None or output is None:
            return False
        write_gv_yaml(
            output,
            {
                "gv_name": name,
                "gv_va": hex(address),
                "gv_rva": hex(address - image_base),
                "gv_sig": signature,
                "gv_sig_va": hex(instruction),
                "gv_inst_offset": "0x0",
                "gv_inst_length": hex(access["insn_len"]),
                "gv_inst_disp": hex(displacement),
                **resolution,
            },
        )
    return await preserve_global_identities(
        session, [_output_for_symbol(expected_outputs, name) for name in located["globals"]], platform
    )
