"""Identity and current-artifact checks for the native RCON behavior locators."""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols, select_symbol

SVEN_LINUX_NAMES = {
    "Cbuf_Execute": "_Z12Cbuf_Executev",
    "NET_Config": "_Z10NET_Configi",
    "NET_IsLocalAddress": "_Z18NET_IsLocalAddress8netadr_s",
    "SVC_ServiceChallenge": "_Z20SVC_ServiceChallengev",
    "SV_Rcon": "_Z7SV_RconP8netadr_s",
    "SV_Rcon_Validate": "_Z16SV_Rcon_Validatev",
    "SV_FlushRedirect": "_Z16SV_FlushRedirectv",
    "SV_CheckForRcon": "_Z15SV_CheckForRconv",
    "SV_CheckChallenge": "_Z17SV_CheckChallengeP8netadr_si",
    "_Host_Frame": "_Z11_Host_Framef",
    "NET_GetPacket": "_Z13NET_GetPacket8netsrc_s",
    "NET_SendPacket": "_Z14NET_SendPacket8netsrc_siPv8netadr_s",
    "SV_FilterPacket": "_Z15SV_FilterPacketv",
    "SV_SendBan": "_Z10SV_SendBanv",
    "SV_HandleRconPacket": "_Z19SV_HandleRconPacketv",
    "SV_CheckRconFailure": "_Z19SV_CheckRconFailureP8netadr_s",
    "SV_AddFailedRcon": "_Z16SV_AddFailedRconP8netadr_s",
    "Cmd_ExecuteString": "_Z17Cmd_ExecuteStringPc12cmd_source_t",
    "SV_BeginRedirect": "_Z16SV_BeginRedirect10redirect_tP8netadr_s",
    "SV_EndRedirect": "_Z14SV_EndRedirectv",
}

CALL_GRAPH_PY = r"""
def native_rcon_edges(start):
    targets = set()
    for ea in idautils.FuncItems(int(start)):
        if (idc.print_insn_mnem(ea) or '').lower() not in ('call', 'jmp'):
            continue
        # Include compiler tail calls, never indirect pointers or local blocks.
        if ida_bytes.get_byte(ea) not in (0xE8, 0xE9):
            continue
        for ref in idautils.CodeRefsFrom(ea, False):
            target = resolve_elf_plt(int(ref))
            f = ida_funcs.get_func(target)
            if f is not None and int(f.start_ea) == target and target != int(start):
                targets.add(target)
    return targets
"""


def function_identity(new_binary_dir, platform, name):
    if platform == "linux" and Path(new_binary_dir).parent.name == "svencoop-8948":
        return SVEN_LINUX_NAMES.get(name, name)
    return name


async def verify_function(session, new_binary_dir, platform, image_base, name):
    identity = "CEngine::Frame" if name == "CEngine_Frame" else function_identity(new_binary_dir, platform, name)
    return await inspect_owner_artifact(session, new_binary_dir, platform, image_base, name, func_name=identity)


async def preserve_function_identities(session, expected_outputs, new_binary_dir, platform, image_base, names):
    """Apply retained ELF names only after normal function/signature validation."""
    identities = {name: function_identity(new_binary_dir, platform, name) for name in names}
    renamed = [identity for name, identity in identities.items() if name != identity]
    if not renamed:
        return True
    symbols = await current_elf_symbols(session, renamed)
    for name, identity in identities.items():
        if name == identity:
            continue
        output = _output_for_symbol(expected_outputs, name)
        data = _load_yaml_mapping(output) if output else None
        if not data or int(data["func_va"], 0) != int(image_base) + select_symbol(symbols, identity, STT_FUNC):
            return False
        data["func_name"] = identity
        write_func_yaml(output, data)
    return True
