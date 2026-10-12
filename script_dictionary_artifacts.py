"""Publish real dictionary identities and body-covering validation signatures.

The retained 5.15 ELF identities are independently correlated with both PE32
inputs and the stripped 5.16 ELF. Tiny bodies may need the explicit
across-function-boundary signature budget; discovery never uses these outputs.
"""

from pathlib import Path

import yaml

from ida_analyze_util import _inspect_function_via_mcp, write_func_yaml

FUNCTION_IDENTITIES = {
    "RegisterScriptDictionary": "RegisterScriptDictionary(asIScriptEngine*)",
    "RegisterScriptDictionary_Native": "RegisterScriptDictionary_Native(asIScriptEngine*)",
    "ScriptDictionaryFactory_Generic": "ScriptDictionaryFactory_Generic(asIScriptGeneric*)",
    "CScriptDictionary_Create": "CScriptDictionary::Create(asIScriptEngine*)",
    "CScriptDictionary_AddRef": "CScriptDictionary::AddRef() const",
    "CScriptDictionary_Release": "CScriptDictionary::Release() const",
    "CScriptDictionary_Set": "CScriptDictionary::Set(const CString&, void*, int)",
    "CScriptDictionary_Get": "CScriptDictionary::Get(const CString&, void*, int) const",
    "CScriptDictionary_Exists": "CScriptDictionary::Exists(const CString&) const",
    "CScriptDictionary_IsEmpty": "CScriptDictionary::IsEmpty() const",
    "CScriptDictionary_GetSize": "CScriptDictionary::GetSize() const",
    "CScriptDictionary_Delete": "CScriptDictionary::Delete(const CString&)",
    "CScriptDictionary_DeleteAll": "CScriptDictionary::DeleteAll()",
}
BODY_SIGNATURE_BYTE_LIMIT = 256


async def publish_dictionary_identities(session, expected_outputs, platform, image_base):
    for output in expected_outputs:
        path = Path(output)
        symbol = path.name.removesuffix(f".{platform}.yaml")
        old = yaml.safe_load(path.read_text(encoding="utf-8"))
        entry = int(old["func_va"], 0)
        identity = FUNCTION_IDENTITIES[symbol]
        # Include actual body statements beyond SEH/PIC headers. Output-only
        # validation stays separate from string/registration/body discovery.
        payload = await _inspect_function_via_mcp(
            session, entry, image_base, identity, signature_byte_limit=BODY_SIGNATURE_BYTE_LIMIT
        )
        if payload is None:
            payload = await _inspect_function_via_mcp(
                session,
                entry,
                image_base,
                identity,
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
