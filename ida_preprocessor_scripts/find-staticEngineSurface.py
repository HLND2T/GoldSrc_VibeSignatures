#!/usr/bin/env python3
"""Recover staticEngineSurface from the VGuiWrap_Startup owner.

``engine/vgui_intwrap.cpp`` holds ``EngineSurfaceWrap *staticEngineSurface`` and
VGuiWrap_Startup opens with ``if (staticEngineSurface) return;`` before
constructing the panel and calling ``engineFactory(ENGINE_SURFACE_VERSION, ...)``.
MetaHookSv instead arms on the ``push 0F0h; push 140h; push 0; push 0`` Panel
constructor sequence, which is shared with unrelated VGUI code.

The guard owner is the anchor: its signature becomes the global's ``gv_sig``.
The reproducible invariant is the guard itself: among the functions that name
the ``EngineSurface007`` interface version, exactly one reads a writable global
in one of its first instructions, and the same function writes that global
later. The reader identifies VGuiWrap_Startup (the version literal is also
owned by the singleton registrar and the factory path), and the write separates
the cached surface pointer from the sibling ``staticPanel`` handle. SvEngine
Windows splits the store into a helper that neither names the literal nor
constructs the panel, so there the owner is recognised by the same
entry-read/body-write pair alone. The finder fails closed unless exactly one
candidate exists. No LLM step and no byte signature participate.
"""

from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

OWNER_NAME = "VGuiWrap_Startup"
GV_NAME = "staticEngineSurface"
INTERFACE_VERSION = "EngineSurface007"
ENTRY_LIMIT = 3

WALK = r"""
import ida_funcs, ida_idp, ida_nalt, idautils

literal = values['literal']

owners = {}
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
for item in strings:
    if str(item) != literal:
        continue
    for xref in idautils.XrefsTo(int(item.ea), 0):
        function = ida_funcs.get_func(int(xref.frm))
        if function is not None:
            owners.setdefault(int(function.start_ea), []).append(int(xref.frm))


def reg4_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def null_test_global(entries, index):
    # A zero comparison against one writable global, in either shipped form.
    entry = entries[index]
    if len(entry['targets']) != 1 or entry['written']:
        return None
    gv = int(next(iter(entry['targets'])))
    disasm = (entry['disasm'] or '').rstrip()
    if entry['mnem'] == 'cmp' and disasm.endswith(', 0'):
        return gv
    if entry['mnem'] != 'mov':
        return None
    insn = entry['insn']
    if int(insn.ops[0].type) != int(idaapi.o_reg):
        return None
    # The register may be spilled to the stack before the test.
    for later in entries[index + 1:index + 4]:
        if later['mnem'] == 'test':
            pass
        elif later['mnem'] == 'push':
            continue
        elif later['mnem'] == 'mov' and int(later['insn'].ops[0].type) == int(idaapi.o_displ) \
                and reg4_name(later['insn'].ops[0]) in ('esp', 'ebp'):
            continue
        else:
            return None
        if later['mnem'] != 'test':
            continue
        later_insn = later['insn']
        if (int(later_insn.ops[0].type) == int(idaapi.o_reg)
                and int(later_insn.ops[1].type) == int(idaapi.o_reg)
                and int(later_insn.ops[0].reg) == int(later_insn.ops[1].reg)
                and int(later_insn.ops[0].reg) == int(insn.ops[0].reg)):
            return gv
        return None
    return None


candidates = []
for owner in sorted(owners):
    entries = scan(owner)
    if entries is None:
        continue
    addresses = [int(entry['ea']) for entry in entries]
    written = {int(gv) for entry in entries for gv in entry['written']}
    for site in owners[owner]:
        try:
            target = addresses.index(int(site))
        except ValueError:
            continue
        # The startup guard is the null test closest above the interface
        # literal reference; staticEngineSurface is the global it tests, which
        # the same body caches later. Guards that follow the reference belong to
        # the sibling singleton/startup path, not to VGuiWrap_Startup.
        for index in range(target - 1, -1, -1):
            gv = null_test_global(entries, index)
            if gv is None:
                continue
            if gv in written:
                candidates.append({'owner': owner, 'gv': gv, 'index': index})
            break

if len(candidates) != 1:
    result = {'error': 'staticEngineSurface guard is not unique',
              'owners': [hex(o) for o in sorted(owners)],
              'candidates': [{'owner': hex(c['owner']), 'gv': hex(c['gv'])}
                             for c in candidates]}
else:
    candidate = candidates[0]
    gv = candidate['gv']
    entries = scan(candidate['owner'])
    indexes = [index for index, entry in enumerate(entries) if gv in entry['targets']]
    carrier = first_addressable(entries, indexes)
    located = access(carrier, gv) if carrier is not None else None
    if located is None:
        result = {'error': 'no addressable staticEngineSurface reference'}
    else:
        result = {'pointer_size': 4, 'owner_ea': hex(candidate['owner']), 'gv': located}
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
    located = await run_walk(session, WALK, {"literal": INTERFACE_VERSION, "entry_limit": ENTRY_LIMIT})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    owner = await owner_context(session, int(located["owner_ea"], 0), image_base, OWNER_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: failed to inspect the guard owner")
        return False
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]})
