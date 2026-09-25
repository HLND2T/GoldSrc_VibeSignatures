"""Body-guard checks for the GL_BuildLightmaps finder.

The finder's R_NewMap branch resolves GL_BuildLightmaps through an LLM
found_call. A wrong call in that run still produces a self-consistent artifact
for the wrong function, so the guard re-checks the accepted body against
lightmap-rebuilder evidence before the artifact may stand. These tests drive the
shipped ``BODY_GUARD_PY`` template and the ``preprocess_skill`` rejection path
with synthetic databases; no IDA and no network are required.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
FINDER_PATH = ROOT / "ida_preprocessor_scripts" / "find-GL_BuildLightmaps.py"

O_IMM = 1
GUARD_MARKER = "surface-name asterisk compare"
THUNK_MARKER = "calc_thunk_func_target"


def load_finder():
    spec = importlib.util.spec_from_file_location("find_gl_buildlightmaps_under_test", FINDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINDER = load_finder()


class Insn:
    """One synthetic instruction: mnemonic, immediate operands, rendered text."""

    def __init__(self, mnemonic, immediates=(), disasm=None):
        self.mnemonic = mnemonic
        self.immediates = list(immediates)
        self.disasm = disasm or mnemonic


class FakeIdb:
    """Drive the shipped guard template against mutable synthetic functions."""

    def __init__(self, functions, *, is_64bit=False):
        self.functions = functions
        self.is_64bit = is_64bit

    def get_func(self, ea):
        if ea not in self.functions:
            return None
        return SimpleNamespace(start_ea=ea, end_ea=ea + len(self.functions[ea]) * 5)

    def instruction(self, ea):
        for start, body in self.functions.items():
            for index, insn in enumerate(body):
                if start + index * 5 == ea:
                    return insn
        return None

    def func_items(self, ea):
        body = self.functions.get(ea)
        if body is None:
            return []
        return [ea + index * 5 for index in range(len(body))]

    def modules(self):
        return {
            "ida_funcs": SimpleNamespace(get_func=self.get_func),
            "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
            "ida_ua": SimpleNamespace(
                insn_t=lambda: SimpleNamespace(ops=[]),
                decode_insn=self.decode_insn,
                o_imm=O_IMM,
            ),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: self.is_64bit),
            "idautils": SimpleNamespace(FuncItems=self.func_items),
            "idc": SimpleNamespace(
                print_insn_mnem=self.print_insn_mnem,
                generate_disasm_line=self.generate_disasm_line,
            ),
        }

    def decode_insn(self, insn, ea):
        current = self.instruction(ea)
        if current is None:
            return 0
        insn.ops = [SimpleNamespace(type=O_IMM, value=value) for value in current.immediates]
        return 5

    def print_insn_mnem(self, ea):
        current = self.instruction(ea)
        return current.mnemonic if current is not None else ""

    def generate_disasm_line(self, ea, _flags):
        current = self.instruction(ea)
        return current.disasm if current is not None else ""

    def guard(self, func_ea):
        return json.loads(run_guard(self, func_ea))


def run_guard(idb, func_ea):
    code = (
        FINDER.BODY_GUARD_PY.replace("FUNC_EA_PLACEHOLDER", str(int(func_ea)))
        .replace("ASTERISK_IMMEDIATE_PLACEHOLDER", hex(FINDER.ASTERISK_IMMEDIATE))
        .replace("TEXTURE_UNIT_IMMEDIATE_PLACEHOLDER", hex(FINDER.TEXTURE_UNIT_IMMEDIATE))
        .replace("FILTER_IMMEDIATES_PLACEHOLDER", repr(list(FINDER.FILTER_IMMEDIATES)))
    )
    # Mirror MCP py_eval exactly: the IDA modules are present in the globals it
    # builds, and the code runs with separate global and local namespaces. A
    # single shared namespace would hide module-level names leaking into main().
    modules = idb.modules()
    globals_ns = {**modules, "__builtins__": __builtins__}
    locals_ns = {}
    with patch.dict("sys.modules", modules):
        exec(compile(code, "<body-guard>", "exec"), globals_ns, locals_ns)
    return locals_ns["result"]


def guard_session(idb, *, body_ea=0x1000, thunk_ea=0x1000, failure=None, seen=None):
    """Answer both py_eval queries: the thunk probe and the body guard."""

    async def call_tool(tool, args):
        assert tool == "py_eval"
        code = args["code"]
        if seen is not None:
            seen.append(code)
        if THUNK_MARKER in code:
            return {"func_va": hex(thunk_ea)}
        assert GUARD_MARKER in code
        return run_guard(idb, body_ea)

    return SimpleNamespace(call_tool=AsyncMock(side_effect=failure or call_tool))


def texparameter_body(*, asterisk=True):
    """The lightmap upload loop: rebind, then qglTexParameterf(GL_TEXTURE_2D, ...)."""
    body = []
    if asterisk:
        body.append(Insn("cmp", [0x2A], "cmp byte ptr [eax], 2Ah ; '*'"))
    body += [
        Insn("push", [0x0DE1, 0x2800], "push 2800h"),
        Insn("push", [0x0DE1, 0x2801], "push 2801h"),
    ]
    return body


class GuardAcceptanceTests(unittest.TestCase):
    def test_lightmap_rebuilder_body_is_accepted(self):
        idb = FakeIdb({0x1000: texparameter_body()})
        payload = idb.guard(0x1000)
        self.assertEqual(4, payload["pointer_size"])
        self.assertEqual(["cmp byte ptr [eax], 2Ah"], payload["asterisk_lines"])

    def test_register_form_asterisk_compare_is_accepted(self):
        # cof-5936 compares the model name through a register, not a byte load.
        body = [Insn("cmp", [0x2A], "cmp ecx, 2Ah")] + texparameter_body(asterisk=False)
        idb = FakeIdb({0x1D6F519: body})
        self.assertEqual(4, idb.guard(0x1D6F519)["pointer_size"])

    def test_immediate_that_is_not_a_compare_is_not_evidence(self):
        body = [Insn("mov", [0x2A], "mov eax, 2Ah")] + texparameter_body(asterisk=False)
        idb = FakeIdb({0x1000: body})
        self.assertIn("asterisk compare", idb.guard(0x1000)["error"])


class GuardRejectionTests(unittest.TestCase):
    def test_plain_r_newmap_callee_is_rejected(self):
        # The hl-3248 regression: V_InitLevel was accepted as GL_BuildLightmaps.
        idb = FakeIdb({0x1DC9E50: [Insn("push", [0x34], "push 34h")]})
        error = idb.guard(0x1DC9E50)["error"]
        self.assertIn("surface-name asterisk compare", error)
        self.assertIn("GL_TEXTURE_2D texparameter target", error)
        self.assertIn("lightmap texture filter texparameter arguments", error)

    def test_texture_heavy_sibling_without_asterisk_compare_is_rejected(self):
        # R_LoadSkys shares the texture IDs but never skips '*' models.
        idb = FakeIdb({0x1D4F8F2: texparameter_body(asterisk=False)})
        error = idb.guard(0x1D4F8F2)["error"]
        self.assertIn("surface-name asterisk compare", error)
        self.assertNotIn("GL_TEXTURE_2D", error)

    def test_missing_filter_arguments_are_reported(self):
        body = [Insn("cmp", [0x2A], "cmp byte ptr [eax], 2Ah"), Insn("push", [0x0DE1], "push 0DE1h")]
        idb = FakeIdb({0x1000: body})
        error = idb.guard(0x1000)["error"]
        self.assertIn("lightmap texture filter texparameter arguments", error)
        self.assertNotIn("asterisk compare", error)

    def test_func_va_that_is_not_a_function_start_is_rejected(self):
        idb = FakeIdb({0x1000: texparameter_body()})
        self.assertIn("not a function start", idb.guard(0x1002)["error"])

    def test_64_bit_database_fails_closed(self):
        idb = FakeIdb({0x1000: texparameter_body()}, is_64bit=True)
        self.assertIn("32-bit database", idb.guard(0x1000)["error"])


class VerifiedBodyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write_artifact(self, func_va="0x1000"):
        output = self.directory / "GL_BuildLightmaps.windows.yaml"
        output.write_text(
            yaml.safe_dump({"func_name": "GL_BuildLightmaps", "func_va": func_va, "func_sig": "55 8B EC"}),
            encoding="utf-8",
        )
        return output

    async def test_accepted_body_verifies(self):
        idb = FakeIdb({0x1000: texparameter_body()})
        self.assertTrue(await FINDER._verified_body(guard_session(idb), self.write_artifact()))

    async def test_rejected_body_does_not_verify(self):
        idb = FakeIdb({0x1000: [Insn("push", [0x34], "push 34h")]})
        self.assertFalse(await FINDER._verified_body(guard_session(idb), self.write_artifact()))

    async def test_thunk_va_is_resolved_before_the_body_scan(self):
        # svencoop-8948/linux reaches the body through a GOT jump stub.
        idb = FakeIdb({0x2000: texparameter_body()})
        output = self.write_artifact(func_va="0x1A2380")
        seen = []
        session = guard_session(idb, body_ea=0x2000, thunk_ea=0x2000, seen=seen)
        self.assertTrue(await FINDER._verified_body(session, output))
        thunk_code, guard_code = seen
        self.assertIn("current_ea = 1713024", thunk_code)  # the stub the artifact names
        self.assertIn("FUNC_EA = 8192", guard_code)  # the body that was guarded

    async def test_transport_failure_fails_closed(self):
        session = guard_session(FakeIdb({}), failure=RuntimeError("py_eval unavailable"))
        self.assertFalse(await FINDER._verified_body(session, self.write_artifact()))

    async def test_unresolvable_thunk_fails_closed(self):
        output = self.write_artifact()
        with patch.object(FINDER, "_resolve_jmp_thunk_target_via_mcp", AsyncMock(return_value=None)):
            self.assertFalse(await FINDER._verified_body(guard_session(FakeIdb({})), output))

    async def test_missing_func_va_fails_closed(self):
        output = self.directory / "GL_BuildLightmaps.windows.yaml"
        output.write_text("func_name: GL_BuildLightmaps\n", encoding="utf-8")
        self.assertFalse(await FINDER._verified_body(guard_session(FakeIdb({})), output))

    async def test_absent_artifact_fails_closed(self):
        missing = self.directory / "GL_BuildLightmaps.windows.yaml"
        self.assertFalse(await FINDER._verified_body(guard_session(FakeIdb({})), missing))

    async def test_guard_judges_the_artifact_entry(self):
        # The artifact decides which body is inspected, not the caller's guess.
        idb = FakeIdb({0x2000: texparameter_body(), 0x3000: [Insn("push", [0x34], "push 34h")]})
        output = self.write_artifact(func_va="0x2000")
        self.assertTrue(await FINDER._verified_body(guard_session(idb, body_ea=0x2000, thunk_ea=0x2000), output))
        rejected = self.write_artifact(func_va="0x3000")
        self.assertFalse(await FINDER._verified_body(guard_session(idb, body_ea=0x3000, thunk_ea=0x3000), rejected))


class PreprocessSkillTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "GL_BuildLightmaps.windows.yaml"

    async def run_skill(self, idb, *, preprocess_succeeds=True, body_ea=0x1000):
        def write_artifact(**_kwargs):
            if preprocess_succeeds:
                self.output.write_text(
                    yaml.safe_dump({"func_name": "GL_BuildLightmaps", "func_va": "0x1000", "func_sig": "55 8B EC"}),
                    encoding="utf-8",
                )
            return preprocess_succeeds

        session = guard_session(idb, body_ea=body_ea, thunk_ea=0x1000)
        with patch.object(FINDER, "preprocess_common_skill", AsyncMock(side_effect=write_artifact)):
            return await FINDER.preprocess_skill(
                session,
                "find-GL_BuildLightmaps",
                [self.output],
                None,
                self.directory,
                "windows",
                0,
            )

    async def test_verified_artifact_is_kept(self):
        self.assertTrue(await self.run_skill(FakeIdb({0x1000: texparameter_body()})))
        self.assertTrue(self.output.is_file())

    async def test_rejected_artifact_is_removed_and_skill_fails(self):
        # The essential guarantee: a wrong candidate never survives as output.
        idb = FakeIdb({0x1000: [Insn("push", [0x34], "push 34h")]})
        self.assertFalse(await self.run_skill(idb))
        self.assertFalse(self.output.exists())

    async def test_body_of_a_texture_sibling_is_removed(self):
        idb = FakeIdb({0x1000: texparameter_body(asterisk=False)})
        self.assertFalse(await self.run_skill(idb))
        self.assertFalse(self.output.exists())

    async def test_common_skill_failure_propagates_without_a_guard_run(self):
        idb = FakeIdb({0x1000: texparameter_body()})
        self.assertFalse(await self.run_skill(idb, preprocess_succeeds=False))
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
