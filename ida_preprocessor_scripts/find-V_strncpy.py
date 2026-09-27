#!/usr/bin/env python3
"""Locate the engine string-copy call that receives the "english" default.

``engine/filesystem.cpp`` seeds the game language with
``Q_strncpy( language, "english", sizeof(language) )`` when no language is
configured, once in FileSystem_SetGameDirectory and once in
FileSystem_AddFallbackGameDir. CaptionMod and VGUI2Extension redirect that call
so a forced or Steam language replaces the built-in default, so the deliverable
is the call instruction; the shipped builds reach the engine's own
``Q_strncpy`` / ``V_strncpy`` or the CRT ``strcpy`` / ``strncpy`` directly.

MetaHookSv searches ``68 80 00 00 00 50`` (``push 80h; push eax``), which occurs
dozen of times per binary and is not a unique anchor. Here the anchor is the
source argument: every reference to an ``english`` literal whose first branch is
a string-copy call. Builds differ in how many copies of the literal they embed
(one to five) and whether more than one is copied, so every literal is examined
and the lowest-addressed copy call is emitted — that is
``FileSystem_SetGameDirectory``, which runs before the fallback-directory pass.
The literal is also compared with ``stricmp``/``strcasecmp`` in the same
translation units, so the discriminator is the callee class — a copy, never a
comparison.

Older MSVC builds (hl-3248/3266/3329/3647/4554) reference the literal only in
the ``__strcmpi`` language probe, with ``Q_strncpy`` inlined as a
length-prechecked byte loop, so they declare no ``V_strncpy`` symbol and are not
registered for this finder. Should a registered build lose the call, the finder
returns ``absent_ok`` with a debug diagnostic instead of fabricating an address.
No LLM step participates.
"""

from ida_analyze_util import _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._patch_signature_common import run_signature
from ida_skill_preprocessor import PREPROCESS_STATUS_ABSENT_OK

LITERAL = "english"
PATCH_NAME = "V_strncpy"
CALL_WINDOW = 6

COPY_NAMES = ("strncpy", "strcpy", "q_strncpy", "v_strncpy", "strlcpy", "strncpy_s")

WALK = r"""
import ida_funcs, ida_nalt, idautils

literal = values['literal']
window = int(values['window'])
copy_names = tuple(values['copy_names'])

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
            addresses = [int(entry['ea']) for entry in entries]
            try:
                start = addresses.index(int(xref.frm))
            except ValueError:
                continue
            for entry in entries[start + 1:start + 1 + window]:
                if entry['mnem'] not in ('call', 'jmp'):
                    continue
                if any(name in (entry['disasm'] or '').lower() for name in copy_names):
                    sites[int(entry['ea'])] = {'owner': int(function.start_ea),
                                               'ea': int(entry['ea']),
                                               'disasm': entry['disasm']}
                break
    ordered = sorted(sites.items(), key=lambda item: (item[1]['owner'], item[0]))
    result = {'pointer_size': 4,
              'sites': [{'owner': hex(s['owner']), 'ea': hex(s['ea']), 'disasm': s['disasm']}
                        for _, s in ordered]}
"""


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
    output = _output_for_symbol(expected_outputs, PATCH_NAME)
    if output is None:
        return False
    located = await run_walk(
        session,
        WALK,
        {"literal": LITERAL, "window": CALL_WINDOW, "copy_names": list(COPY_NAMES)},
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    sites = located.get("sites") or []
    if not sites:
        if debug:
            print(f"{skill_name}: no string-copy call consumes the english default")
        return PREPROCESS_STATUS_ABSENT_OK
    try:
        patch_ea = int(sites[0]["ea"], 0)
        owner_ea = int(sites[0]["owner"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    if patch_ea < owner_ea or patch_ea < int(image_base):
        return False
    generated = await run_signature(session, patch_ea)
    if generated is None:
        if debug:
            print(f"{skill_name}: no unique signature at {sites[0].get('ea')}")
        return False
    if debug:
        print(f"{skill_name}: ea={sites[0]['ea']} {sites[0]['disasm']}")
    write_patch_yaml(
        output,
        {
            "patch_name": PATCH_NAME,
            "patch_va": hex(patch_ea),
            "patch_rva": hex(patch_ea - int(image_base)),
            "patch_sig": generated["patch_sig"],
            "patch_sig_disp": generated["patch_sig_disp"],
        },
    )
    return True
