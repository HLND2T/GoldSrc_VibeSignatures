"""Publish verified AngelScript callable identities under the consumer's filenames.

Names follow the retained Sven 5.15 ELF symbols; the 5.16 and Windows bodies
were independently correlated. This only labels validated function artifacts.
"""

from pathlib import Path

import yaml

from ida_analyze_util import write_func_yaml

FUNCTION_IDENTITIES = {
    "CASRefCountedBaseClass_InternalRelease": "CASRefCountedBaseClass::InternalRelease() const",
    "CScriptAny_Release": "CScriptAny::Release() const",
    "CScriptArray_Release": "CScriptArray::Release() const",
    "CASBaseCallable_Call": "CASBaseCallable::Call(int, ...)",
    "CASFunction_Create": "CASFunction::Create(asIScriptFunction*, CASModule*, bool)",
}


def publish_callable_identities(expected_outputs, platform):
    for output in expected_outputs:
        path = Path(output)
        symbol = path.name.removesuffix(f".{platform}.yaml")
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        payload["func_name"] = FUNCTION_IDENTITIES[symbol]
        write_func_yaml(path, payload)
