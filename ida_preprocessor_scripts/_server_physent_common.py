"""Shared artifact identities for the server movement conversion locators."""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols

FUNCTION_SYMBOLS = {
    "SV_AddLinksToPM_": "_Z16SV_AddLinksToPM_P10areanode_sPfS1_",
    "NUM_FOR_EDICT": "_Z13NUM_FOR_EDICTPK7edict_s",
    "SV_CopyEdictToPhysent": "_Z21SV_CopyEdictToPhysentP9physent_siP7edict_s",
}


async def preserve_functions(session, outputs, platform, image_base, names):
    if platform != "linux":
        return True
    symbols = await current_elf_symbols(session, list(names) + [FUNCTION_SYMBOLS[n] for n in names])
    for name in names:
        output = _output_for_symbol(outputs, name)
        data = _load_yaml_mapping(output)
        matches = {
            symbol
            for symbol, value, kind in symbols
            if kind == STT_FUNC and value + int(image_base) == int(data["func_va"], 0)
        }
        if len(matches) > 1:
            return False
        if matches:
            data["func_name"] = matches.pop()
            write_func_yaml(output, data)
    return True
