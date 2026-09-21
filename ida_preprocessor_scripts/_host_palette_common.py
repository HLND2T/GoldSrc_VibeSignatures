"""Direct locators for Host_Init palette/texture private symbols."""

import inspect

from ida_analyze_util import _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts import x86_call_arguments
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, owner_context, run_walk
from ida_preprocessor_scripts.host_basepal_store import locate_palette_hunk_store

HOST_INIT_NAME = "Host_Init"
HOST_LOAD_BASE_PALETTE_NAME = "Host_LoadBasePalette"
HUNK_ALLOC_NAME = "Hunk_AllocName"
HOST_BASEPAL_NAME = "host_basepal"
PALETTE_LMP_NAME = "palette.lmp"
PALETTE_LMP_PREFIX = "gfx/"
R_INIT_TEXTURES_NAME = "R_InitTextures"
R_NOTEXTURE_MIP_NAME = "r_notexture_mip"
R_UPLOAD_EMPTY_TEX_NAME = "R_UploadEmptyTex"
R_EMPTYTEXTURE_NAME = "r_emptytexture"
R_UPLOAD_MISSING_TEX_NAME = "R_UploadMissingTex"
R_MISSINGTEXTURE_NAME = "r_missingtexture"

HOST_INIT_PALETTE_ERROR = "Host_Init: Couldn't load gfx/palette.lmp"
HOST_INIT_HEAP_SIZE = "Heap size: %4.1f MB\n"
HOST_LOAD_PALETTE_ERROR = 'Could not load base palette from "%s".\n'
HUNK_PALETTE_SIZE = 0x800
CUSTOM_HPAK_NAME = "custom"
EMPTY_TEX_NAME = "**empty**"
MISSING_TEX_NAME = "**missing**"
NOTEXTURE_HUNK_NAME = "notexture"
GL_DUMP_COMMAND = "gl_dump"

FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]

HOST_INIT_XREF_SPECS = [
    [
        {
            "func_name": HOST_INIT_NAME,
            "xref_strings": [f"FULLMATCH:{HOST_INIT_PALETTE_ERROR}"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        }
    ],
    [
        {
            "func_name": HOST_INIT_NAME,
            "xref_strings": [f"FULLMATCH:{HOST_INIT_HEAP_SIZE}"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        }
    ],
]
HOST_LOAD_BASE_PALETTE_XREFS = [
    {
        "func_name": HOST_LOAD_BASE_PALETTE_NAME,
        "xref_strings": [f"FULLMATCH:{HOST_LOAD_PALETTE_ERROR}"],
        "exclude_strings": [f"FULLMATCH:{HOST_INIT_HEAP_SIZE}"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    }
]
R_UPLOAD_EMPTY_XREFS = [
    {
        "func_name": R_UPLOAD_EMPTY_TEX_NAME,
        "xref_strings": [f"FULLMATCH:{EMPTY_TEX_NAME}"],
        "exclude_strings": [f"FULLMATCH:{MISSING_TEX_NAME}", f"FULLMATCH:{GL_DUMP_COMMAND}"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    }
]
R_UPLOAD_MISSING_XREFS = [
    {
        "func_name": R_UPLOAD_MISSING_TEX_NAME,
        "xref_strings": [f"FULLMATCH:{MISSING_TEX_NAME}"],
        "exclude_strings": [f"FULLMATCH:{EMPTY_TEX_NAME}"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    }
]

WALK_HELPERS = r"""
def string_owners(literal):
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    matches = [int(item.ea) for item in strings if str(item) == literal]
    owners = set()
    for ea in matches:
        for ref in idautils.XrefsTo(ea, 0):
            function = ida_funcs.get_func(int(ref.frm))
            if function is not None:
                owners.add(int(function.start_ea))
    return owners


def unique_remaining(positive, excluded=()):
    owners = string_owners(positive)
    for literal in excluded:
        owners.difference_update(string_owners(literal))
    return sorted(owners)[0] if len(owners) == 1 else None


def exact_bytes(ea):
    raw = ida_bytes.get_strlit_contents(int(ea), -1, 0)
    return bytes(raw) if raw else b''
"""

WALK_HOST_BASEPAL = (
    WALK_HELPERS
    + inspect.getsource(x86_call_arguments)
    + "\n"
    + inspect.getsource(locate_palette_hunk_store)
    + r"""
import ida_frame
import ida_name
import ida_ua

HUNK = int(values['hunk_ea'], 0)
SIZE = int(values['size_imm'])
NAME = values['name']
PREFIX = values['name_prefix']
owner = unique_remaining(values['sven_positive'], values['sven_exclude'])
if owner is None:
    owner = exact_string_owner(values['goldsrc_literal'])
if owner is None:
    result = {'error': 'palette owner is not unique'}
else:
    entries = scan(owner)
    func = ida_funcs.get_func(owner)
    if entries is None or func is None:
        result = {'error': 'palette owner is not a function start'}
    else:
        name_addrs = set()
        strings = idautils.Strings(default_setup=False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
        for item in strings:
            text = str(item)
            if text == NAME:
                name_addrs.add(int(item.ea))
            elif text == PREFIX + NAME:
                name_addrs.add(int(item.ea) + len(PREFIX))
        if not name_addrs:
            result = {'error': 'palette.lmp string is missing', 'owner_ea': hex(owner)}
        else:
            got_base, got_register = got_anchor(owner)

            def normalize_thunk_name(name):
                name = name or ''
                if name.startswith('j_'):
                    name = name[2:]
                if name.startswith('.'):
                    name = name[1:]
                if name.startswith('_imp_'):
                    name = name[5:]
                return name

            def pic_plt_callee(call_ea):
                # SvEngine Linux PIC PLT: call stub; jmp [ebx+GOTOFF]. Lazy .got.plt
                # still holds stub+6, so resolve_elf_plt's dword==target check fails.
                if got_base is None or idc.get_operand_type(int(call_ea), 0) != int(idaapi.o_near):
                    return None
                stub = int(idc.get_operand_value(int(call_ea), 0))
                if not is_plt(stub):
                    return None
                function = ida_funcs.get_func(stub)
                if function is not None and int(function.start_ea) == stub:
                    thunk_target, _slot = ida_funcs.calc_thunk_func_target(function)
                    if thunk_target != idaapi.BADADDR and not is_plt(int(thunk_target)):
                        callee = ida_funcs.get_func(int(thunk_target))
                        if callee is not None and int(callee.start_ea) == int(thunk_target):
                            return int(thunk_target)
                insn = idautils.DecodeInstruction(int(stub))
                if insn is None or (idc.print_insn_mnem(int(stub)) or '').lower() != 'jmp':
                    return None
                op = insn.ops[0]
                kind = int(op.type)
                slot = None
                if kind == int(idaapi.o_mem) and is_got(int(op.addr)):
                    slot = int(op.addr) & 0xFFFFFFFF
                elif kind in (int(idaapi.o_displ), int(idaapi.o_phrase)) and reg4(op) == got_register:
                    slot = (got_base + signed32(op.addr)) & 0xFFFFFFFF
                if slot is None or not is_got(slot):
                    return None
                pointee = int(ida_bytes.get_dword(slot)) & 0xFFFFFFFF
                if is_code_address(pointee) and not is_plt(pointee):
                    callee = ida_funcs.get_func(pointee)
                    if callee is not None and int(callee.start_ea) == pointee:
                        return pointee
                found = set()
                for ref in idautils.DataRefsFrom(slot):
                    ref = int(ref)
                    if is_code_address(ref) and not is_plt(ref):
                        callee = ida_funcs.get_func(ref)
                        if callee is not None and int(callee.start_ea) == ref:
                            found.add(ref)
                for xref in idautils.XrefsTo(HUNK, 0):
                    if int(xref.frm) == slot:
                        found.add(int(HUNK))
                if len(found) == 1:
                    return next(iter(found))
                hunk_name = normalize_thunk_name(ida_name.get_name(int(HUNK)))
                if hunk_name and hunk_name in (
                    normalize_thunk_name(ida_name.get_name(stub)),
                    normalize_thunk_name(ida_name.get_name(slot)),
                ):
                    return int(HUNK)
                return None

            def hunk_callee(call_ea):
                return pic_plt_callee(call_ea) or local_call_target(call_ea)

            code = []
            for entry in entries:
                sp = int(ida_frame.get_spd(func, entry['ea']))
                operands = []
                mnem = entry['mnem']
                for index, op in enumerate(entry['insn'].ops):
                    kind = int(op.type)
                    if kind == int(idaapi.o_void):
                        break
                    operand = ('unknown', None)
                    if kind == int(idaapi.o_reg):
                        if index == 0 or ida_ua.get_dtype_size(op.dtype) == 4:
                            operand = ('reg', reg4(op))
                    elif kind == int(idaapi.o_imm):
                        operand = ('imm', int(op.value) & 0xFFFFFFFF)
                    elif kind in (int(idaapi.o_near), int(idaapi.o_far)):
                        operand = ('imm', int(idc.get_operand_value(entry['ea'], index)) & 0xFFFFFFFF)
                    elif kind in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                        text = (idc.print_operand(entry['ea'], index) or '').lower()
                        if '[esp' in text and not any(
                            register in text for register in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')
                        ):
                            displacement = signed32(op.addr) if kind == int(idaapi.o_displ) else 0
                            if ida_ua.get_dtype_size(op.dtype) == 4 and displacement % 4 == 0:
                                operand = ('stack', sp + displacement)
                    operands.append(operand)
                if mnem == 'lea' and len(operands) == 2:
                    source = entry['insn'].ops[1]
                    address = None
                    if int(source.type) == int(idaapi.o_mem):
                        address = int(source.addr) & 0xFFFFFFFF
                    elif (
                        int(source.type) == int(idaapi.o_displ)
                        and got_base is not None
                        and reg4(source) == got_register
                    ):
                        address = (got_base + signed32(source.addr)) & 0xFFFFFFFF
                    if address in name_addrs:
                        mnem = 'mov'
                        operands[1] = ('imm', address)
                if operands and operands[0][0] == 'reg' and ida_ua.get_dtype_size(entry['insn'].ops[0].dtype) != 4:
                    mnem = 'unknown_write'
                code.append(
                    {
                        'mnem': mnem,
                        'ops': operands,
                        'sp': sp,
                        'written': set(entry['written']),
                        'call_target': hunk_callee(entry['ea']) if mnem == 'call' else None,
                        'ea': entry['ea'],
                        'disp': entry['disp'],
                        'len': entry['len'],
                        'disasm': entry['disasm'],
                    }
                )
            located = locate_palette_hunk_store(code, HUNK, SIZE, name_addrs)
            if located.get('error'):
                result = dict(located)
                result['owner_ea'] = hex(owner)
                result['hunk_ea'] = hex(HUNK)
                result['got'] = [hex(got_base) if got_base is not None else None, got_register]
                result['name_addrs'] = [hex(addr) for addr in sorted(name_addrs)]
                calls = []
                for index, entry in enumerate(code):
                    if entry['mnem'] != 'call':
                        continue
                    args = recover_call_arguments(code, index, 2)
                    calls.append(
                        {
                            'ea': hex(int(entry['ea'])),
                            'disasm': entry.get('disasm') or '',
                            'target': hex(int(entry['call_target'])) if entry.get('call_target') else None,
                            'args': [hex(arg) if isinstance(arg, int) else arg for arg in args],
                        }
                    )
                result['calls'] = calls
            else:
                result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located['gv']}
"""
)

WALK_R_INIT_TEXTURES = (
    WALK_HELPERS
    + r"""
owner = int(values['host_init_ea'], 0)
needle = values['custom'].encode('latin1')
entries = scan(owner)
if entries is None:
    result = {'error': 'Host_Init artifact is not a function start'}
else:
    custom_indexes = []
    for index, entry in enumerate(entries):
        for ref in idautils.DataRefsFrom(int(entry['ea'])):
            if exact_bytes(ref) == needle:
                custom_indexes.append(index)
                break
    if len(custom_indexes) != 1:
        result = {'error': 'Host_Init custom HPAK xref is not unique: %s' % custom_indexes}
    else:
        callee = None
        for index in range(custom_indexes[0] - 1, -1, -1):
            if entries[index]['mnem'] != 'call':
                continue
            callee = local_call_target(entries[index]['ea'])
            break
        if callee is None:
            result = {'error': 'no R_InitTextures call before custom HPAK'}
        else:
            result = {'pointer_size': 4, 'owner_ea': hex(callee)}
"""
)

WALK_UNIQUE_WRITE = r"""
owner = int(values['owner_ea'], 0)
entries = scan(owner)
if entries is None:
    result = {'error': 'owner is not a function start'}
else:
    written = {}
    for index, entry in enumerate(entries):
        if len(entry['written']) != 1:
            continue
        gv = next(iter(entry['written']))
        written.setdefault(gv, []).append(index)
    if len(written) != 1:
        result = {'error': 'writable global store is not unique: %s' % [hex(gv) for gv in written]}
    else:
        gv, indexes = next(iter(written.items()))
        located = access(first_addressable(entries, indexes), gv)
        if located is None:
            result = {'error': 'no addressable unique store'}
        else:
            result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located}
"""

WALK_UNIQUE_BODY_GV = r"""
owner = int(values['owner_ea'], 0)
prefix = int(values['skip_prefix'])
entries = scan(owner)
if entries is None:
    result = {'error': 'owner is not a function start'}
else:
    mapping = single_globals(entries)
    start = int(entries[0]['ea'])
    body = []
    for gv, indexes in mapping.items():
        if any(int(entries[index]['ea']) >= start + prefix for index in indexes):
            body.append(gv)
    if len(body) != 1:
        result = {'error': 'body global is not unique: %s' % [hex(gv) for gv in body]}
    else:
        gv = body[0]
        located = access(first_addressable(entries, mapping[gv]), gv)
        if located is None:
            result = {'error': 'no addressable body global'}
        else:
            result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located}
"""


async def locate_function_by_xrefs(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    func_name,
    func_xrefs,
    debug=False,
):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[func_name],
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=[(func_name, list(FUNC_FIELDS))],
        debug=debug,
    )


async def locate_function_first_xref_spec(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    func_name,
    xref_specs,
    debug=False,
):
    for func_xrefs in xref_specs:
        if await locate_function_by_xrefs(
            session,
            expected_outputs,
            new_binary_dir,
            platform,
            image_base,
            func_name,
            func_xrefs,
            debug=debug,
        ):
            return True
    return False


async def emit_optional_gv(session, expected_outputs, platform, image_base, owner_name, gv_name, located, debug=False):
    if _output_for_symbol(expected_outputs, gv_name) is None:
        return True
    if located.get("error") or located.get("pointer_size") != 4 or "gv" not in located:
        if debug:
            print(f"  {gv_name}: {located.get('error') or located}")
        return False
    owner = await owner_context(session, int(located["owner_ea"], 0), image_base, owner_name)
    if owner is None:
        if debug:
            print(f"  {gv_name}: could not revalidate {owner_name}")
        return False
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {gv_name: located["gv"]},
    )


async def preprocess_host_init(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    return await locate_function_first_xref_spec(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        HOST_INIT_NAME,
        HOST_INIT_XREF_SPECS,
        debug=debug,
    )


async def preprocess_host_load_base_palette(
    session, expected_outputs, new_binary_dir, platform, image_base, debug=False
):
    return await locate_function_by_xrefs(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        HOST_LOAD_BASE_PALETTE_NAME,
        HOST_LOAD_BASE_PALETTE_XREFS,
        debug=debug,
    )


async def preprocess_host_basepal(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    hunk = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, HUNK_ALLOC_NAME)
    if hunk is None:
        if debug:
            print(f"  {HOST_BASEPAL_NAME}: missing {HUNK_ALLOC_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK_HOST_BASEPAL,
        {
            "sven_positive": HOST_LOAD_PALETTE_ERROR,
            "sven_exclude": [HOST_INIT_HEAP_SIZE],
            "goldsrc_literal": HOST_INIT_PALETTE_ERROR,
            "size_imm": HUNK_PALETTE_SIZE,
            "hunk_ea": hex(hunk["owner_ea"]),
            "name": PALETTE_LMP_NAME,
            "name_prefix": PALETTE_LMP_PREFIX,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {HOST_BASEPAL_NAME}: {located}")
        return False
    owner_ea = int(located["owner_ea"], 0)
    owner = await owner_context(session, owner_ea, image_base, HOST_INIT_NAME)
    if owner is None:
        owner = await owner_context(session, owner_ea, image_base, HOST_LOAD_BASE_PALETTE_NAME)
    if owner is None:
        if debug:
            print(f"  {HOST_BASEPAL_NAME}: could not inspect palette owner {owner_ea:#x}")
        return False
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {HOST_BASEPAL_NAME: located["gv"]},
    )


async def preprocess_r_init_textures(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    func_output = _output_for_symbol(expected_outputs, R_INIT_TEXTURES_NAME)
    if func_output is None:
        return False
    host = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, HOST_INIT_NAME)
    if host is None:
        if debug:
            print(f"  {R_INIT_TEXTURES_NAME}: missing {HOST_INIT_NAME} artifact")
        return False
    located = await run_walk(
        session,
        WALK_R_INIT_TEXTURES,
        {"host_init_ea": hex(host["owner_ea"]), "custom": CUSTOM_HPAK_NAME},
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {R_INIT_TEXTURES_NAME}: {located.get('error') or located}")
        return False
    owner_ea = int(located["owner_ea"], 0)
    function = await inspect_func(session, owner_ea, image_base, R_INIT_TEXTURES_NAME)
    if not function:
        if debug:
            print(f"  {R_INIT_TEXTURES_NAME}: inspect failed at {owner_ea:#x}")
        return False
    write_func_yaml(func_output, function)
    if _output_for_symbol(expected_outputs, R_NOTEXTURE_MIP_NAME) is None:
        return True
    gv_located = await run_walk(session, WALK_UNIQUE_WRITE, {"owner_ea": hex(owner_ea)})
    return await emit_optional_gv(
        session,
        expected_outputs,
        platform,
        image_base,
        R_INIT_TEXTURES_NAME,
        R_NOTEXTURE_MIP_NAME,
        gv_located,
        debug=debug,
    )


async def preprocess_upload_empty(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    if not await locate_function_by_xrefs(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        R_UPLOAD_EMPTY_TEX_NAME,
        R_UPLOAD_EMPTY_XREFS,
        debug=debug,
    ):
        return False
    if _output_for_symbol(expected_outputs, R_EMPTYTEXTURE_NAME) is None:
        return True
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, R_UPLOAD_EMPTY_TEX_NAME)
    if owner is None:
        return False
    located = await run_walk(
        session,
        WALK_UNIQUE_BODY_GV,
        {"owner_ea": hex(owner["owner_ea"]), "skip_prefix": 0x20},
    )
    return await emit_optional_gv(
        session,
        expected_outputs,
        platform,
        image_base,
        R_UPLOAD_EMPTY_TEX_NAME,
        R_EMPTYTEXTURE_NAME,
        located,
        debug=debug,
    )


async def preprocess_upload_missing(session, expected_outputs, new_binary_dir, platform, image_base, debug=False):
    if not await locate_function_by_xrefs(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        R_UPLOAD_MISSING_TEX_NAME,
        R_UPLOAD_MISSING_XREFS,
        debug=debug,
    ):
        return False
    if _output_for_symbol(expected_outputs, R_MISSINGTEXTURE_NAME) is None:
        return True
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, R_UPLOAD_MISSING_TEX_NAME)
    if owner is None:
        return False
    located = await run_walk(
        session,
        WALK_UNIQUE_BODY_GV,
        {"owner_ea": hex(owner["owner_ea"]), "skip_prefix": 0x20},
    )
    return await emit_optional_gv(
        session,
        expected_outputs,
        platform,
        image_base,
        R_UPLOAD_MISSING_TEX_NAME,
        R_MISSINGTEXTURE_NAME,
        located,
        debug=debug,
    )
