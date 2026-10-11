"""Execute the shipped locator with MCP's separate globals/locals namespaces."""

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "gl_load_filter_texture", ROOT / "ida_preprocessor_scripts/find-GL_LoadFilterTexture.py"
)
FINDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINDER)

FIRST = 0x1000
SECOND = 0x2000
GL_BIND = 0x8000
MALLOC = 0x9000
FUNCTION_SIZE = 0x80
O_IMM = 5


class FakeIdbSession:
    def __init__(self, callees, *, immediate_type=O_IMM):
        self.callees = callees
        self.immediate_type = immediate_type
        self.renamed = []

    def modules(self):
        def get_func(ea):
            if ea in self.callees:
                return SimpleNamespace(start_ea=ea, end_ea=ea + FUNCTION_SIZE)
            return None

        def decode_instruction(ea):
            if ea in self.callees:
                return SimpleNamespace(
                    ops=[SimpleNamespace(type=self.immediate_type, value=value, dtype=4) for value in (0xC0, 0x1907)]
                )
            return SimpleNamespace(ops=[])

        def xrefs_from(ea, _flags):
            return [SimpleNamespace(to=callee) for callee in self.callees.get(ea - 1, ())]

        return {
            "ida_bytes": SimpleNamespace(get_bytes=lambda _ea, _size: b"\xc0\x00\x00\x00\x07\x19\x00\x00"),
            "ida_funcs": SimpleNamespace(get_func=get_func),
            "ida_nalt": SimpleNamespace(),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, o_imm=O_IMM),
            "idautils": SimpleNamespace(
                Functions=lambda: list(self.callees),
                FuncItems=lambda ea: [ea, ea + 1],
                DecodeInstruction=decode_instruction,
                XrefsFrom=xrefs_from,
            ),
            "idc": SimpleNamespace(
                print_insn_mnem=lambda ea: "push" if ea in self.callees else "call",
                generate_disasm_line=lambda _ea, _flags: "call helper",
                get_func_name=lambda ea: f"sub_{ea:x}",
            ),
            "ida_ua": SimpleNamespace(get_dtype_size=lambda dtype: dtype),
            "ida_name": SimpleNamespace(
                get_name=lambda ea: "malloc" if ea == MALLOC else "helper",
                SN_FORCE=1,
                set_name=lambda ea, name, _flags: self.renamed.append((ea, name)),
            ),
        }

    async def call_tool(self, tool, args):
        if tool != "py_eval":
            raise AssertionError(f"Unexpected MCP tool: {tool}")
        modules = self.modules()
        globals_ns = {**modules, "__builtins__": __builtins__}
        locals_ns = {}
        # Python <=3.11 comprehensions have their own scope. Sharing these two
        # dictionaries would hide the CI regression in a module-level loop.
        with patch.dict("sys.modules", modules):
            exec(compile(args["code"], "<py_eval>", "exec"), globals_ns, locals_ns)  # noqa: S102 - shipped MCP script
        return locals_ns["result"]


class FilterTextureLocatorTests(unittest.IsolatedAsyncioTestCase):
    async def assert_located(self, session, glbind_ea, expected_ea, expected_stage):
        payload = await FINDER._locate_filter_texture(session, glbind_ea)
        self.assertNotIn("error", payload)
        self.assertEqual(4, payload["pointer_size"])
        self.assertEqual(hex(expected_ea), payload["func_ea"])
        self.assertEqual(hex(FUNCTION_SIZE), payload["func_size"])
        self.assertEqual(expected_stage, payload["stage"])
        self.assertEqual([(expected_ea, "GL_LoadFilterTexture")], session.renamed)

    async def test_glbind_wins_over_allocator_discriminator(self):
        session = FakeIdbSession({FIRST: (MALLOC,), SECOND: (GL_BIND,)})
        await self.assert_located(session, GL_BIND, SECOND, "glbind")

    async def test_allocator_disambiguates_without_glbind(self):
        session = FakeIdbSession({FIRST: (), SECOND: (MALLOC,)})
        await self.assert_located(session, 0, SECOND, "allocfree")

    async def test_allocator_disambiguates_after_ambiguous_glbind(self):
        session = FakeIdbSession({FIRST: (GL_BIND,), SECOND: (GL_BIND, MALLOC)})
        await self.assert_located(session, GL_BIND, SECOND, "allocfree")

    async def test_unique_constant_pair_survives_unmatched_discriminators(self):
        session = FakeIdbSession({FIRST: ()})
        await self.assert_located(session, GL_BIND, FIRST, "constants")

    async def test_ambiguous_constant_pair_is_rejected_without_renaming(self):
        session = FakeIdbSession({FIRST: (), SECOND: ()})
        payload = await FINDER._locate_filter_texture(session, 0)
        self.assertEqual("GL_LoadFilterTexture constant pair is not unique", payload["error"])
        self.assertEqual([hex(FIRST), hex(SECOND)], [record["ea"] for record in payload["matches"]])
        self.assertEqual([], session.renamed)

    async def test_byte_constants_in_non_immediate_operands_are_rejected(self):
        session = FakeIdbSession({FIRST: (GL_BIND,)}, immediate_type=O_IMM + 1)
        payload = await FINDER._locate_filter_texture(session, GL_BIND)
        self.assertEqual("GL_LoadFilterTexture constant pair is not unique", payload["error"])
        self.assertEqual([], payload["matches"])
        self.assertEqual([], session.renamed)


if __name__ == "__main__":
    unittest.main()
