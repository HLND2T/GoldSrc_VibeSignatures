#!/usr/bin/env python3
"""Locate both filesystem copies of the default language, independently of names.

The source statement in engine/filesystem.cpp is
``Q_strncpy(language, "english", sizeof(language))`` with a local 128-byte buffer.
Follow each exact literal reference through its basic block and direct jumps to
the copy, including a shared Steam/default-language call tail. Decode all three
arguments; a comparison, two-argument strcpy, or unrelated object field fails.

The owners also reference the localized search-path format ``%s/%s_%s`` and
``GAME``. ``DEFAULTGAME`` distinguishes FileSystem_SetGameDirectory (V_strncpy)
from FileSystem_AddFallbackGameDir (V_strncpy_FallbackGameDir). Both must be
unique and present; address order and IDA-inferred callee names are irrelevant.
Consumers redirect both sites. Older registry-based tags have no default-English
copy and use find-Sys_GetRegKeyValueUnderRoot instead. Unexpected absence in a
registered build is a failure.
"""

import inspect

from ida_analyze_util import _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._engine_patch_common import CALL_FLOW_PY, language_role
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._patch_signature_common import run_signature

LITERAL = "english"
PATCH_NAMES = ("V_strncpy", "V_strncpy_FallbackGameDir")

WALK = (
    CALL_FLOW_PY
    + "\n"
    + inspect.getsource(language_role)
    + r"""
import ida_funcs, ida_nalt, idautils

literal = values['literal']

literal_eas = []
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) == literal:
        literal_eas.append(int(item.ea))

if not literal_eas:
    result = {'error': 'english literal is absent'}
else:
    sites = {}
    for literal_ea in literal_eas:
        for xref in idautils.XrefsTo(literal_ea, 0):
            function = ida_funcs.get_func(int(xref.frm))
            if function is None:
                continue
            entries = scan(int(function.start_ea))
            if entries is None:
                continue
            owner = int(function.start_ea)
            code = decoded_calls(owner, entries)
            path = anchored_call_path(owner, code, int(xref.frm))
            if path is None:
                continue
            arguments = recover_call_arguments(path, len(path) - 1, 3)
            role = language_role(arguments, owner_strings(entries), literal_eas)
            if role is None:
                continue
            ea = path[-1]['ea']
            sites[ea] = {'name': role, 'owner': hex(owner), 'ea': hex(ea),
                         'arguments': arguments, 'disasm': idc.generate_disasm_line(ea, 0)}
    result = {'pointer_size': 4,
              'sites': list(sites.values())}
"""
)


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = old_yaml_map, new_binary_dir
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in PATCH_NAMES}
    if not all(outputs.values()):
        return False
    located = await run_walk(
        session,
        WALK,
        {"literal": LITERAL},
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    sites = located.get("sites") or []
    if len(sites) != len(PATCH_NAMES) or {site.get("name") for site in sites} != set(PATCH_NAMES):
        if debug:
            print(f"{skill_name}: expected one language copy in each filesystem owner")
        return False
    payloads = {}
    for site in sites:
        try:
            patch_ea = int(site["ea"], 0)
            owner_ea = int(site["owner"], 0)
        except (TypeError, ValueError, KeyError):
            return False
        if patch_ea < owner_ea or patch_ea < int(image_base):
            return False
        generated = await run_signature(session, patch_ea)
        if generated is None:
            return False
        payloads[site["name"]] = {
            "patch_name": site["name"],
            "patch_va": hex(patch_ea),
            "patch_rva": hex(patch_ea - int(image_base)),
            "patch_sig": generated["patch_sig"],
            "patch_sig_disp": generated["patch_sig_disp"],
        }
    for name, payload in payloads.items():
        write_patch_yaml(outputs[name], payload)
    return True
