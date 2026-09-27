#!/usr/bin/env python3
"""Locate the VGUIClient001 factory call inside CBaseUI__Initialize.

``engine/vgui2/BaseUI_Interface.cpp`` CBaseUI::Initialize calls
``clientDLLFactory( CLIENTVGUI_INTERFACE_VERSION, NULL )`` after retrieving the
factory from the client DLL. VGUI2Extension redirects that call to its own
``VGUIClient001_CreateInterface`` so a mirrored engine can be hooked, so the
deliverable is the call instruction, not the callee.

MetaHookSv searches a hand-written byte pattern around the pushed interface
string. Here the anchor is the interface literal itself: ``VClientVGUI001`` has
exactly one instance and one owning function on every configured engine build,
and that owner references the literal once — as the factory call's second
argument. The factory call is therefore the first branch after the reference
site. The finder revalidates the produced CBaseUI__Initialize artifact and fails
closed on anything but one reference site and one following call. No LLM step
participates.
"""

from ida_analyze_util import _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._patch_signature_common import run_signature

OWNER_NAME = "CBaseUI__Initialize"
INTERFACE_VERSION = "VClientVGUI001"
PATCH_NAME = "VGUIClient001_CreateInterface"
CALL_WINDOW = 8

WALK = r"""
import ida_funcs, ida_nalt, idautils

owner = int(values['owner'], 0)
literal = values['literal']
window = int(values['window'])

literal_ea = None
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) == literal:
        literal_ea = int(item.ea)
        break

if literal_ea is None:
    result = {'error': 'interface literal is absent'}
else:
    sites = []
    for xref in idautils.XrefsTo(literal_ea, 0):
        function = ida_funcs.get_func(int(xref.frm))
        if function is not None and int(function.start_ea) == owner:
            sites.append(int(xref.frm))
    sites = sorted(set(sites))
    if len(sites) != 1:
        result = {'error': 'interface literal reference is not unique in owner',
                  'sites': [hex(s) for s in sites]}
    else:
        entries = scan(owner)
        if entries is None:
            result = {'error': 'CBaseUI__Initialize artifact is not a function start'}
        else:
            addresses = [int(entry['ea']) for entry in entries]
            try:
                start = addresses.index(sites[0])
            except ValueError:
                start = None
            if start is None:
                result = {'error': 'literal reference is not an instruction in owner'}
            else:
                call = None
                for entry in entries[start + 1:start + 1 + window]:
                    if entry['mnem'] in ('call', 'jmp'):
                        call = entry
                        break
                if call is None:
                    result = {'error': 'no branch follows the interface literal'}
                else:
                    result = {'pointer_size': 4, 'owner_ea': hex(owner),
                              'reference': hex(sites[0]),
                              'site': {'ea': hex(int(call['ea'])),
                                       'mnem': call['mnem'],
                                       'disasm': call['disasm']}}
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
    _ = old_yaml_map
    output = _output_for_symbol(expected_outputs, PATCH_NAME)
    if output is None:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: missing or invalid {OWNER_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK,
        {"owner": hex(owner["owner_ea"]), "literal": INTERFACE_VERSION, "window": CALL_WINDOW},
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    site = located.get("site")
    if not isinstance(site, dict):
        return False
    try:
        patch_ea = int(site["ea"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    owner_ea = int(owner["owner_ea"])
    if not owner_ea <= patch_ea < int(owner["owner_end"]):
        return False
    generated = await run_signature(session, patch_ea)
    if generated is None:
        if debug:
            print(f"{skill_name}: no unique signature at {site.get('ea')}")
        return False
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
