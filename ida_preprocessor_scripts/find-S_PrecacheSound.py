#!/usr/bin/env python3
"""Locate S_PrecacheSound through its sound-name lookup transfers and lazy cache call.

``engine/snd_dma.c`` S_PrecacheSound owns no diagnostic of its own: it tests
``sound_started``/``nosound.value``, rejects names of MAX_QPATH length, branches on
``name[0] == '!' || name[0] == '*'`` between two ``S_FindName(name, NULL)`` lookups,
and guards one ``S_LoadSound(sfx, NULL)`` call behind ``fs_lazy_precache.value``.

The finder therefore starts from the ``S_FindName`` body recovered by the
``find-S_FindName`` artifact and its own guard literal ``"S_FindName: NULL\\n"``:

- the artifact entry plus every other function owning the guard literal covers the GCC
  ``pfInCache == NULL`` specializations (``S_FindName.constprop.N`` on hl-8684, which is
  the body S_PrecacheSound itself calls while ``VOX_LoadSound`` keeps the generic one),
- candidates are the callers of ``S_LoadSound`` resolved past PLT stubs (the shared
  ``callers`` walk; svencoop-8948 routes every call through ``.plt``/``.plt.got``),
- a candidate must transfer into a FindName-family body at least twice (``call`` or the
  tail ``jmp`` the ``'!'``/``'*'`` branch compiles to on GCC),
- a candidate must be console-quiet: no ``Cmd_*``/``Con_*`` callee (demangled past the
  GNU v3 ``_Z<len><name>`` PLT-stub spelling) and no read-only string-literal
  reference. That excludes ``S_Play``, ``S_PlayVol``, ``S_Say`` and ``S_Say_Reliable``
  (console-command owners with ``Cmd_Argc``/``Cmd_Argv`` and format strings),
  ``S_LocalSound`` (``Con_Printf("S_LocalSound: can't cache %s\\n")`` — the call is
  ``.plt.got``-routed and unnamed on svencoop-8948, so the owned literal is the stable
  evidence) and ``VOX_LoadSound`` (single lookup, ``"vox/"`` literals).

Exactly one candidate must survive; zero or multiple candidates fail closed. Verified
targets: hl-10210 hw.dll ``0x101fdc50``, hl-10210/hl-8684/svencoop-10257 hw.so
``0x196b10``/``0x1e6050``/``0x163c10`` (constprop-clone path), svencoop-10257 hw.dll
``0x1d97d30``, svencoop-8948 hw.so ``0x1afb30`` (PLT path). No byte signature
participates in discovery.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

FUNC_NAME = "S_PrecacheSound"
SFN_NAME = "S_FindName"
SLS_NAME = "S_LoadSound"
LITERAL = "S_FindName: NULL\n"

WALK = r"""
import re as _re

findname = int(values['findname'], 0)
loadsound = int(values['loadsound'], 0)

# FindName-family bodies: the artifact entry plus every other owner of the guard
# literal (GCC constprop specializations).
strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=6)
literals = [int(item.ea) for item in strings if str(item) == values['literal']]
if len(literals) != 1:
    result = {'error': 'S_FindName guard literal must occur exactly once',
              'literals': [hex(ea) for ea in literals]}
else:
    family = {findname}
    for ref in idautils.XrefsTo(literals[0], 0):
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            family.add(int(function.start_ea))

    # S_LoadSound callers, PLT stubs resolved.
    candidates = {caller for caller, site in callers(loadsound)}

    gnu3 = _re.compile(r'_Z(\d+)')

    def plain_name(name):
        # A PLT stub may be spelled ".<mangled>"; reduce to the plain function name.
        if not name:
            return ''
        if name.startswith('.'):
            name = name[1:]
        if name.startswith('_Z'):
            match = gnu3.match(name)
            if match:
                length = int(match.group(1))
                start = 2 + len(match.group(1))
                return name[start:start + length]
        return name

    def string_literal_ref(start):
        # S_PrecacheSound reads only cvar structs and GOT slots; every competitor owns
        # at least one read-only diagnostic/format literal.
        for ea in idautils.FuncItems(start):
            for ref in idautils.DataRefsFrom(ea):
                if idc.get_segm_name(ref) in ('.rodata', '.rdata', '.data.rel.ro') \
                        and idc.get_strlit_contents(ref, -1, ida_nalt.STRTYPE_C):
                    return True
        return False

    hits = []
    detail = {}
    for start in sorted(candidates):
        transfers = 0
        console = set()
        for ea in idautils.FuncItems(start):
            mnemonic = (idc.print_insn_mnem(ea) or '').lower()
            if mnemonic not in ('call', 'jmp'):
                continue
            if idc.get_operand_type(ea, 0) != int(idaapi.o_near):
                continue
            target = int(idc.get_operand_value(ea, 0))
            callee = ida_funcs.get_func(target)
            entry = int(callee.start_ea) if callee is not None else target
            if (mnemonic == 'call' and entry in family) or (mnemonic == 'jmp' and target in family):
                transfers += 1
            if mnemonic == 'call':
                name = plain_name(idc.get_func_name(target) or '')
                if name.startswith(('Cmd_', 'Con_')):
                    console.add(name)
        literal_ref = string_literal_ref(start)
        detail[hex(start)] = {'transfers': transfers, 'console': sorted(console),
                              'literal_ref': literal_ref}
        if transfers >= 2 and not console and not literal_ref:
            hits.append(start)

    if len(hits) != 1:
        result = {'error': 'exactly one S_PrecacheSound candidate must survive',
                  'hits': [hex(h) for h in hits], 'candidates': detail}
    else:
        result = {'pointer_size': 4, 'target': hex(hits[0]),
                  'candidates': detail}
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
    _ = old_yaml_map, platform
    output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if output is None:
        return False

    findname = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, SFN_NAME)
    if findname is None:
        if debug:
            print(f"{skill_name}: missing or invalid {SFN_NAME} artifact")
        return False
    loadsound = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, SLS_NAME)
    if loadsound is None:
        if debug:
            print(f"{skill_name}: missing or invalid {SLS_NAME} artifact")
        return False

    located = await run_walk(
        session,
        WALK,
        {
            "literal": LITERAL,
            "findname": hex(findname["owner_ea"]),
            "loadsound": hex(loadsound["owner_ea"]),
        },
    )
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False

    target = int(located["target"], 0)
    function = await inspect_func(session, target, image_base, FUNC_NAME)
    if function is None:
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: {FUNC_NAME}={target:#x}")
    return True
