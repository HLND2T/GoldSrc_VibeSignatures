"""Direct locators for Host_Init palette/texture private symbols."""

from ida_analyze_util import _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, owner_context, run_walk

HOST_INIT_NAME = "Host_Init"
HOST_LOAD_BASE_PALETTE_NAME = "Host_LoadBasePalette"
HOST_BASEPAL_NAME = "host_basepal"
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
    + r"""
owner = unique_remaining(values['sven_positive'], values['sven_exclude'])
if owner is None:
    owner = exact_string_owner(values['goldsrc_literal'])
if owner is None:
    result = {'error': 'palette owner is not unique'}
else:
    entries = scan(owner)
    if entries is None:
        result = {'error': 'palette owner is not a function start'}
    else:
        size_imm = int(values['size_imm'])
        candidates = []
        for index, entry in enumerate(entries):
            if entry['mnem'] == 'cmp':
                continue
            has_size = False
            for op in entry['insn'].ops:
                if int(op.type) == int(idaapi.o_void):
                    break
                if int(op.type) == int(idaapi.o_imm) and (int(op.value) & 0xFFFFFFFF) == size_imm:
                    has_size = True
            if not has_size:
                continue
            call_index = None
            for follow in range(index + 1, min(index + 6, len(entries))):
                if entries[follow]['mnem'] == 'call':
                    call_index = follow
                    break
            if call_index is None:
                continue
            for store in range(call_index + 1, min(call_index + 8, len(entries))):
                if entries[store]['mnem'] == 'call':
                    break
                if len(entries[store]['written']) != 1:
                    continue
                gv = next(iter(entries[store]['written']))
                located = access(entries[store] if entries[store]['disp'] else None, gv)
                if located is None:
                    located = access(first_addressable(entries, [store]), gv)
                if located is not None:
                    candidates.append((gv, located))
                break
        unique = {}
        for gv, located in candidates:
            unique[gv] = located
        if len(unique) != 1:
            result = {
                'error': 'Hunk_AllocName(0x800) store is not unique: %s' % [hex(gv) for gv in unique],
                'owner_ea': hex(owner),
            }
        else:
            gv, located = next(iter(unique.items()))
            result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located}
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
    _ = new_binary_dir
    located = await run_walk(
        session,
        WALK_HOST_BASEPAL,
        {
            "sven_positive": HOST_LOAD_PALETTE_ERROR,
            "sven_exclude": [HOST_INIT_HEAP_SIZE],
            "goldsrc_literal": HOST_INIT_PALETTE_ERROR,
            "size_imm": HUNK_PALETTE_SIZE,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {HOST_BASEPAL_NAME}: {located.get('error') or located}")
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
