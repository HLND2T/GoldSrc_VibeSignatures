"""Publish verified CAS directory/manager method identities after discovery.

The Linux GetTypeInfoByName parameter uses the libstdc++ __cxx11 string ABI,
as established by the 5.15 ELF symbol and the 5.16 caller/callee dataflow.
These names label validated artifacts; they never participate in discovery.
"""

from pathlib import Path

import yaml

from ida_analyze_util import write_func_yaml

FUNCTION_IDENTITIES = {
    "CASDirectoryList_CreateDirectory": (
        "CASDirectoryList::CreateDirectory(char const*, unsigned char, unsigned char, unsigned char, unsigned char)"
    ),
    "CASPersistence_KeepIfPrevious": "CASPersistence::KeepIfPrevious(CScriptArray const*)",
    "CASBaseManager_GetTypeInfoByName": "CASBaseManager::GetTypeInfoByName(std::string const&)",
}
LINUX_TYPE_INFO_IDENTITY = (
    "CASBaseManager::GetTypeInfoByName("
    "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)"
)


def publish_directory_manager_identities(expected_outputs, platform):
    for output in expected_outputs:
        path = Path(output)
        symbol = path.name.removesuffix(f".{platform}.yaml")
        identity = FUNCTION_IDENTITIES[symbol]
        if platform == "linux" and symbol == "CASBaseManager_GetTypeInfoByName":
            identity = LINUX_TYPE_INFO_IDENTITY
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        payload["func_name"] = identity
        write_func_yaml(path, payload)
