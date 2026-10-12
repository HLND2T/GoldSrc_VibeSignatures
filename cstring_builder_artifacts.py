"""Publish Part E source identities and output-only function signatures.

Discovery uses registration literals and verified calls, never these signatures.
The byte budget reaches body statements beyond MSVC SEH/GCC PIC headers. Tiny
destructor adapters may need an explicit across-function-boundary output budget.
"""

from pathlib import Path

import yaml

from ida_analyze_util import _inspect_function_via_mcp, write_func_yaml

FUNCTION_IDENTITIES = {
    "RegisterSCScriptASString": "RegisterSCScriptASString(asIScriptEngine*, CASDocumentation*)",
    "CASModuleBuilder_CASModuleBuilder": "CASModuleBuilder::CASModuleBuilder(ModuleType::Type, const char*)",
    "CString_opAssign": "CString::operator=(const CString&)",
    "DestructASString": "DestructASString(CString*)",
    "CString_Assign": "CString::Assign(const char*, unsigned int)",
    "CString_dtor": "CString::~CString()",
    "CScriptBuilder_DefineWord": "CScriptBuilder::DefineWord(const char*)",
}
BODY_SIGNATURE_BYTE_LIMIT = 256


async def publish_identities(session, expected_outputs, platform, image_base):
    for output in expected_outputs:
        path = Path(output)
        symbol = path.name.removesuffix(f".{platform}.yaml")
        entry = int(yaml.safe_load(path.read_text(encoding="utf-8"))["func_va"], 0)
        payload = await _inspect_function_via_mcp(
            session, entry, image_base, FUNCTION_IDENTITIES[symbol], signature_byte_limit=BODY_SIGNATURE_BYTE_LIMIT
        )
        if payload is None:
            payload = await _inspect_function_via_mcp(
                session,
                entry,
                image_base,
                FUNCTION_IDENTITIES[symbol],
                allow_across_function_boundary=True,
                signature_byte_limit=BODY_SIGNATURE_BYTE_LIMIT,
            )
            if payload is not None:
                payload["func_sig_allow_across_function_boundary"] = True
        if payload is None or int(payload["func_va"], 0) != entry:
            return False
        payload.pop("_pointer_size", None)
        write_func_yaml(path, payload)
    return True
