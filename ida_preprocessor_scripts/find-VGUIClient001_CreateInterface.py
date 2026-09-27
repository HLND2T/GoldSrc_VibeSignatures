#!/usr/bin/env python3
"""Locate the module-to-factory call used by CBaseUI__Initialize.

MetaHookSv replaces Sys_GetFactory(hClientDLL), which returns the factory later
called with ("VClientVGUI001", NULL). Revalidate the owning artifact, recover
those interface-query arguments, and trace its indirect callee back to the
dominating call's return value. Require a global module-handle argument and a
callee body referencing the exact export name "CreateInterface".

The query itself has a different ABI and is never the patch site. Engines using
the zero-argument ClientFactory callback reuse the existing g_pClientFactory
producer instead; they do not register this patch finder.
"""

import inspect

from ida_analyze_util import _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._engine_patch_common import CALL_FLOW_PY, factory_origin
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._patch_signature_common import run_signature

OWNER_NAME = "CBaseUI__Initialize"
INTERFACE_VERSION = "VClientVGUI001"
PATCH_NAME = "VGUIClient001_CreateInterface"

WALK = (
    CALL_FLOW_PY
    + "\n"
    + inspect.getsource(factory_origin).replace("x86_call_arguments.", "")
    + r"""
import ida_funcs, ida_nalt, idautils

owner = int(values['owner'], 0)
literal = values['literal']

literal_eas = []
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) == literal:
        literal_eas.append(int(item.ea))

if len(literal_eas) != 1:
    result = {'error': 'interface literal is absent or ambiguous'}
else:
    sites = []
    for xref in idautils.XrefsTo(literal_eas[0], 0):
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
            code = decoded_calls(owner, entries)
            path = anchored_call_path(owner, code, sites[0])
            if path is None or recover_call_arguments(path, len(path) - 1, 2) != [literal_eas[0], 0]:
                result = {'error': 'interface query arguments are not verified'}
            else:
                exits = compiler_noreturn_imports()
                noreturn_calls = {item['ea'] for item in code if item['mnem'] == 'call'
                                  and int(idc.get_operand_value(item['ea'], 0)) in exits}
                flow = decode_function_flow(ida_funcs.get_func(owner), [item['ea'] for item in code],
                                            noreturn_calls=noreturn_calls)
                for item in code:
                    item['successors'] = flow[item['ea']]
                query_index = next(i for i, item in enumerate(code) if item['ea'] == path[-1]['ea'])
                producer_index = factory_origin(code, query_index)
                call = entries[producer_index] if producer_index is not None else None
                if call is None or int(call['insn'].ops[0].type) != int(idaapi.o_near):
                    result = {'error': 'no direct module factory call; reuse g_pClientFactory for callback engines'}
                else:
                    factory_path = anchored_call_path(owner, code, call['ea'])
                    args = recover_call_arguments(factory_path, len(factory_path) - 1, 1) if factory_path else []
                    callee = local_call_target(call['ea'])
                    body = scan(callee) if callee else None
                    if (not args or not isinstance(args[0], tuple) or args[0][0] != 'global_value'
                            or not is_writable_data(args[0][1])
                            or not body or 'CreateInterface' not in owner_strings(body)):
                        result = {'error': 'module argument or Sys_GetFactory body is not verified', 'arguments':args}
                    else:
                        result = {'pointer_size': 4, 'owner_ea': hex(owner),
                                  'reference': hex(sites[0]),
                                  'site': {'ea': hex(int(call['ea'])),
                                           'mnem': call['mnem'],
                                           'disasm': call['disasm']}}
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
        {"owner": hex(owner["owner_ea"]), "literal": INTERFACE_VERSION},
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
