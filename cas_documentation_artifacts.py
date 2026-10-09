"""Publish real CASDocumentation method identities under stable config filenames.

Linux identities follow the ten verified 5.15 ELF symbols, demangled by c++filt;
5.16 bodies were independently correlated by calls and registration operations.
Windows uses 32-bit unsigned int for AngelScript flags/calling-convention values.
This helper only labels validated artifacts: it does not discover addresses.
"""

from pathlib import Path

import yaml

from ida_analyze_util import write_func_yaml

FUNCTION_ARGUMENTS = {
    "RegisterObjectType": "char const*, char const*, int, unsigned long",
    "RegisterObjectProperty": "char const*, char const*, char const*, int",
    "RegisterGlobalProperty": "char const*, char const*, void*",
    "RegisterGlobalFunction": "char const*, char const*, asSFuncPtr const&, unsigned long, void*",
    "RegisterObjectMethod": "char const*, char const*, char const*, asSFuncPtr const&, unsigned long",
    "RegisterObjectBehaviour": "char const*, char const*, asEBehaviours, char const*, asSFuncPtr const&, unsigned long, void*",
    "RegisterFuncDef": "char const*, char const*",
    "RegisterEnum": "char const*, char const*, CASDocumentation::ENUM_TYPE",
    "RegisterEnumValue": "char const*, char const*, char const*, int",
    "SetDefaultNamespace": "char const*",
}


def publish_documentation_identities(expected_outputs, platform):
    for output in expected_outputs:
        path = Path(output)
        method = path.name.removeprefix("CASDocumentation_").removesuffix(f".{platform}.yaml")
        arguments = FUNCTION_ARGUMENTS[method]
        if platform == "windows":
            arguments = arguments.replace("unsigned long", "unsigned int")
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        payload["func_name"] = f"CASDocumentation::{method}({arguments})"
        write_func_yaml(path, payload)
