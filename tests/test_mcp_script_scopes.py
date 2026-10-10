"""Run MCP locator paths with Python's separate global/local execution scopes."""

import ast
import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ida_analyze_util

ROOT = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts"
FIRST = 0x1000
SECOND = 0x2000
DATA = 0x8000


def template(filename, name="LOCATE_PY", **replacements):
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    )
    code = ast.literal_eval(assignment.value)
    for marker, value in replacements.items():
        code = code.replace(marker, repr(value))
    return code


def execute(code, modules=None, initial=None):
    """Mirror py_eval's statement execution and optional trailing expression."""
    tree = ast.parse(code)
    expression = tree.body.pop() if isinstance(tree.body[-1], ast.Expr) else None
    globals_ns, locals_ns = {}, dict(initial or {})
    with patch.dict("sys.modules", modules or {}):
        exec(compile(tree, "<py_eval>", "exec"), globals_ns, locals_ns)  # noqa: S102 - shipped MCP script
        if expression is not None:
            globals_ns.update(locals_ns)
            value = eval(compile(ast.Expression(expression.value), "<py_eval>", "eval"), globals_ns)
        else:
            value = locals_ns.get("result")
    return json.loads(value) if isinstance(value, str) else locals_ns


def region(code, first_assignment, last_assignment):
    """Exercise a locator's decision block without emulating its entire IDB."""
    tree = ast.parse(code)
    body = []
    for node in tree.body:
        body.extend(node.body if isinstance(node, ast.Try) else [node])

    def assigns(node, name):
        return isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        )

    first = next(index for index, node in enumerate(body) if assigns(node, first_assignment))
    last = next(index for index in range(first + 1, len(body)) if assigns(body[index], last_assignment))
    return ast.unparse(ast.Module(body=body[first:last], type_ignores=[]))


class McpScriptScopeTests(unittest.TestCase):
    def test_texturemode_recovery_checks_every_literal_site_owner(self):
        class Strings(list):
            def setup(self, **_kwargs):
                pass

        class StringItem:
            def __init__(self, value, ea):
                self.value, self.ea = value, ea

            def __str__(self):
                return self.value

        for foreign_owner in (False, True):
            with self.subTest(foreign_owner=foreign_owner):
                defined = set()

                def get_func(ea, defined=defined, foreign_owner=foreign_owner):
                    if ea == FIRST:
                        return SimpleNamespace(start_ea=FIRST)
                    if SECOND in defined and ea == SECOND + 5:
                        return SimpleNamespace(start_ea=FIRST if foreign_owner else SECOND)
                    return None

                modules = {
                    "ida_bytes": SimpleNamespace(get_flags=lambda ea: 1, is_code=lambda flags: True),
                    "ida_funcs": SimpleNamespace(
                        get_func=get_func, add_func=lambda ea, defined=defined: defined.add(ea) or True
                    ),
                    "ida_nalt": SimpleNamespace(STRTYPE_C=0),
                    "idautils": SimpleNamespace(
                        Strings=lambda **kwargs: Strings(
                            [StringItem("filter literal", DATA), StringItem("gl_texturemode", DATA + 4)]
                        ),
                        XrefsTo=lambda ea, flags: [SimpleNamespace(frm=SECOND + 5 if ea == DATA else FIRST)],
                    ),
                    "idc": SimpleNamespace(
                        prev_head=lambda ea: ea - 5,
                        print_insn_mnem=lambda ea: "push",
                        get_operand_value=lambda ea, index: SECOND,
                    ),
                    "idaapi": SimpleNamespace(BADADDR=0xFFFFFFFF),
                }
                code = template(
                    "_engine_texture_mode_common.py",
                    "RECOVER_PY",
                    LITERAL_PLACEHOLDER="filter literal",
                    COMMAND_PLACEHOLDER="gl_texturemode",
                )
                payload = execute(code, modules)
                self.assertNotIn("error", payload)
                self.assertEqual(None if foreign_owner else hex(SECOND), payload["recovered"])

    def test_cvar_hook_call_ambiguity_is_reported(self):
        code = template("find-cvar_hooks.py", CVAR_SET_EA_PLACEHOLDER=FIRST, CVAR_DIRECTSET_EA_PLACEHOLDER=SECOND)
        modules = {name: SimpleNamespace() for name in ("ida_bytes", "ida_gdl", "ida_idp", "ida_name", "ida_segment")}
        modules.update(
            {
                "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 0x40)),
                "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, fl_CN=1, fl_CF=2),
                "idautils": SimpleNamespace(
                    FuncItems=lambda ea: [ea, ea + 5],
                    DecodeInstruction=lambda ea: True,
                    XrefsFrom=lambda ea, flags: [SimpleNamespace(type=1, to=SECOND)],
                ),
                "idc": SimpleNamespace(print_insn_mnem=lambda ea: "call"),
            }
        )
        payload = execute(code, modules)
        self.assertEqual("Cvar_Set direct call to Cvar_DirectSet is not unique", payload["error"])
        self.assertEqual([hex(FIRST), hex(FIRST + 5)], payload["calls"])

    def test_texture_counter_owner_inventory_preserves_sites(self):
        raw = b"\x90" * 16 + b"\xa1" + DATA.to_bytes(4, "little")
        function = SimpleNamespace(start_ea=FIRST, end_ea=FIRST + 0x20)
        modules = {
            "ida_bytes": SimpleNamespace(get_bytes=lambda ea, size: raw if ea == FIRST else b""),
            "ida_funcs": SimpleNamespace(get_func=lambda ea: function),
            "ida_idp": SimpleNamespace(),
            "ida_segment": SimpleNamespace(
                getseg=lambda ea: SimpleNamespace(start_ea=FIRST, end_ea=FIRST + 0x20, perm=4), SEGPERM_EXEC=4
            ),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: False),
            "idautils": SimpleNamespace(Segments=lambda: [FIRST]),
            "idc": SimpleNamespace(get_func_name=lambda ea: "GL_LoadTexture2"),
        }
        code = template(
            "find-texture_extension_number-owners.py",
            GLOBAL_EA_PLACEHOLDER=DATA,
            GL_BIND_EA_PLACEHOLDER=SECOND,
            KNOWN_OWNERS_PLACEHOLDER={FIRST: "GL_LoadTexture2"},
            EXPECTED_NAMES_PLACEHOLDER=["GL_LoadTexture2"],
        )
        payload = execute(code, modules)
        self.assertNotIn("error", payload)
        self.assertEqual([hex(FIRST + 16)], payload["owners"]["GL_LoadTexture2"]["sites"])

    def test_resources_sentinel_lea_compare_retains_operand_identity(self):
        reg = lambda index: SimpleNamespace(type=1, reg=index)
        mem = lambda ea: SimpleNamespace(type=2, addr=ea)
        body = {
            FIRST: SimpleNamespace(ops=[reg(1), mem(DATA)], size=6),
            FIRST + 6: SimpleNamespace(ops=[reg(2), reg(1)], size=2),
            FIRST + 8: SimpleNamespace(ops=[reg(2), mem(DATA + 0x80)], size=6),
        }
        modules = {
            "ida_bytes": SimpleNamespace(),
            "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=FIRST, end_ea=FIRST + 14)),
            "ida_segment": SimpleNamespace(
                getseg=lambda ea: SimpleNamespace(perm=2), get_segm_name=lambda segment: ".data", SEGPERM_WRITE=2
            ),
            "idaapi": SimpleNamespace(
                inf_is_64bit=lambda: False, o_void=0, o_reg=1, o_mem=2, o_displ=3, o_phrase=4, o_imm=5
            ),
            "idautils": SimpleNamespace(
                FuncItems=lambda ea: list(body), DecodeInstruction=lambda ea: body[ea], DataRefsFrom=lambda ea: []
            ),
            "idc": SimpleNamespace(
                print_insn_mnem=lambda ea: {FIRST: "lea", FIRST + 6: "cmp", FIRST + 8: "mov"}[ea],
                generate_disasm_line=lambda ea, flags: "instruction",
            ),
        }
        code = template(
            "find-cl_resourcesonhand.py",
            OWNER_EA_PLACEHOLDER=FIRST,
            PNEXT_OFFSET_PLACEHOLDER=0x80,
            LEA_CMP_WINDOW_PLACEHOLDER=6,
        )
        payload = execute(code, modules)
        self.assertNotIn("error", payload)
        self.assertEqual(DATA, payload["gv_ea"])
        self.assertEqual("lea", payload["source"])
        self.assertEqual(FIRST + 8, payload["load_ea"])

    def test_elf_section_headers_are_parsed_before_rejecting_missing_plt(self):
        binary = bytearray(92)
        binary[:6] = b"\x7fELF\x01\x01"
        struct.pack_into("<H", binary, 18, 3)
        struct.pack_into("<I", binary, 32, 52)
        struct.pack_into("<HHH", binary, 46, 40, 1, 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "engine.so"
            path.write_bytes(binary)
            modules = {name: SimpleNamespace() for name in ("ida_bytes", "ida_funcs", "ida_segment", "idautils", "idc")}
            modules.update(
                {
                    "ida_nalt": SimpleNamespace(get_input_file_path=lambda: str(path), get_imagebase=lambda: 0),
                    "idaapi": SimpleNamespace(inf_is_64bit=lambda: False),
                }
            )
            code = template(
                "find-CUtlVector_gltexture_t_InsertBefore-decompiles.py", "PLT_QUERY", OWNER_PLACEHOLDER=FIRST
            )
            self.assertEqual([], execute(code, modules))

    def test_float_candidate_filter_receives_current_constraints(self):
        code = region(ida_analyze_util._FUNC_XREF_PY_EVAL_TEMPLATE, "required_floats", "items")
        seen = []

        def matches(start, required, excluded):
            seen.append((start, required, excluded))
            return start == SECOND

        namespace = execute(
            code,
            initial={
                "spec": {"xref_floats": [1], "exclude_floats": [2]},
                "candidates": {FIRST, SECOND},
                "_function_matches_float_filters": matches,
            },
        )
        self.assertEqual({SECOND}, namespace["candidates"])
        self.assertEqual([(FIRST, [1.0], [2.0]), (SECOND, [1.0], [2.0])], sorted(seen))

    def test_sprite_access_selection_uses_each_global_and_encoded_width(self):
        code = template("find-Mod_UnloadSpriteTextures.py")
        code = region(code, "accesses", "result")
        records = [
            {"target": DATA, "disp": 1, "length": 5, "ea": FIRST},
            {"target": DATA + 4, "disp": 2, "length": 6, "ea": SECOND},
            {"target": DATA + 4, "disp": 2, "length": 5, "ea": FIRST - 1},
        ]
        namespace = execute(code, initial={"sprite_list": DATA, "sprite_count": DATA + 4, "shutdown_records": records})
        self.assertEqual(FIRST, namespace["accesses"]["gSpriteList"]["ea"])
        self.assertEqual(SECOND, namespace["accesses"]["gSpriteCount"]["ea"])


if __name__ == "__main__":
    unittest.main()
