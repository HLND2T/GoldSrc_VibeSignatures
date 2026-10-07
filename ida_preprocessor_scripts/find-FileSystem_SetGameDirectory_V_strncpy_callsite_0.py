#!/usr/bin/env python3
"""Locate both filesystem copies of the default language, independently of names.

The source statement in engine/filesystem.cpp is
``Q_strncpy(language, "english", sizeof(language))`` with a local 128-byte buffer.
Follow each exact literal reference through its basic block and direct jumps to
the copy, including a shared Steam/default-language call tail. Decode all three
arguments; a comparison, two-argument strcpy, or unrelated object field fails.

The owners also reference the localized search-path format ``%s/%s_%s`` and
``GAME``. ``DEFAULTGAME`` distinguishes FileSystem_SetGameDirectory (FileSystem_SetGameDirectory_V_strncpy_callsite_0)
from FileSystem_AddFallbackGameDir (FileSystem_AddFallbackGameDir_V_strncpy_callsite_0). Both must be
unique and present; address order and IDA-inferred callee names are irrelevant.
Consumers redirect both sites. Older registry-based tags have no default-English
copy and use find-Sys_GetRegKeyValueUnderRoot instead. Unexpected absence in a
registered build is a failure.

Most compilers merge the Steam-language and default-English copies into one
shared ``call`` (both arms jump to it), so one site per owner suffices. CoF
emits one copy per arm instead; there the second copy is emitted as
``..._callsite_1`` and stays optional because merged-call engines never
produce it.
"""

import inspect

from ida_analyze_util import _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._engine_patch_common import CALL_FLOW_PY, branch_tail_call, language_role
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._patch_signature_common import run_signature

LITERAL = "english"
PATCH_NAMES = ("FileSystem_SetGameDirectory_V_strncpy_callsite_0", "FileSystem_AddFallbackGameDir_V_strncpy_callsite_0")


def _callsite_name(base_name, index):
    """Return the artifact name for one copy of a language buffer.

    The base name already ends in ``_callsite_0``; the first copy keeps it and a
    per-branch duplicate becomes ``..._callsite_1``.
    """
    prefix = base_name[: -len("_callsite_0")]
    return base_name if index == 0 else f"{prefix}_callsite_{index}"


WALK = (
    CALL_FLOW_PY
    + "\n"
    + inspect.getsource(branch_tail_call)
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
            # A per-branch compiler emits a second copy of the same destination
            # buffer; its source is the Steam language rather than the literal,
            # so only the destination and the 128-byte size are comparable.
            siblings = [hex(ea)]
            tail = branch_tail_call(owner, code, ea)
            if tail is not None:
                tail_arguments = recover_call_arguments(code, tail, 3)
                if tail_arguments[0] == arguments[0] and tail_arguments[2] == arguments[2]:
                    siblings.append(hex(code[tail]['ea']))
            sites[ea] = {'name': role, 'owner': hex(owner), 'ea': hex(ea), 'sites': siblings}
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
    # The base names are required; the per-branch duplicates carry the numeric
    # `_1` names and stay optional because merged-call engines never emit them.
    optional_outputs = {
        _callsite_name(name, index): _output_for_symbol(expected_outputs, _callsite_name(name, index))
        for name in PATCH_NAMES
        for index in (1,)
    }
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
            owners = [int(owner, 0) for owner in site["sites"]]
            owner_ea = int(site["owner"], 0)
        except (TypeError, ValueError, KeyError):
            return False
        for index, patch_ea in enumerate(owners):
            name = _callsite_name(site["name"], index)
            target = outputs.get(name) or optional_outputs.get(name)
            # An index above the first duplicate is an unexpected third copy.
            if target is None or patch_ea < owner_ea or patch_ea < int(image_base):
                return False
            generated = await run_signature(session, patch_ea)
            if generated is None:
                return False
            payloads[name] = (
                target,
                {
                    "patch_name": name,
                    "patch_va": hex(patch_ea),
                    "patch_rva": hex(patch_ea - int(image_base)),
                    "patch_sig": generated["patch_sig"],
                    "patch_sig_disp": generated["patch_sig_disp"],
                },
            )
    for _, (target, payload) in payloads.items():
        write_patch_yaml(target, payload)
    return True
