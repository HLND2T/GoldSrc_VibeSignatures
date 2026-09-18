import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_finder(filename):
    spec = importlib.util.spec_from_file_location(filename, ROOT / "ida_preprocessor_scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


APP = load_finder("find-CGame_AppActivate.py")
HOST = load_finder("find-SPR_Shutdown-host_initialized.py")


class Block:
    def __init__(self, start, end):
        self.start_ea, self.end_ea = start, end
        self.predecessors, self.successors = [], []

    def preds(self):
        return self.predecessors

    def succs(self):
        return self.successors


class String:
    def __init__(self, ea, text):
        self.ea, self.text = ea, text

    def __str__(self):
        return self.text


class FakeIdb:
    """Exercise the actual locator with mutable IDA function boundaries."""

    def __init__(self, *, gap=False, merged=True, failure=None, owner_tail=False):
        self.owner_start = 0x1000 if merged else 0x1100
        self.functions = {self.owner_start: SimpleNamespace(start_ea=self.owner_start, end_ea=0x1300)}
        self.original = self.boundaries()
        self.failure = failure
        self.mutations = []
        self.owner_tails = [(0x1500, 0x1520)] if owner_tail else []
        root = Block(0x1100, 0x1110)
        tail = Block(0x1120 if gap else 0x1110, 0x1140)
        root.successors, tail.predecessors = [tail], [root]
        self.blocks = [root, tail]
        self.modules = {
            "ida_auto": SimpleNamespace(plan_range=lambda *_: None, auto_wait=self.auto_wait),
            "ida_bytes": SimpleNamespace(get_bytes=lambda ea, size: b"\x90" * size),
            "ida_funcs": SimpleNamespace(
                get_func=self.get_func,
                set_func_end=self.set_func_end,
                add_func=self.add_func,
                del_func=self.del_func,
            ),
            "ida_name": SimpleNamespace(get_name=lambda ea: "sub_1100"),
            "ida_segment": SimpleNamespace(SEGPERM_EXEC=1, getseg=lambda ea: SimpleNamespace(start_ea=0x800, perm=1)),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, FlowChart=lambda func: self.blocks),
            "idautils": SimpleNamespace(
                Strings=lambda: [String(0x2000, APP.ANCHOR_STRINGS[0]), String(0x2100, APP.ANCHOR_STRINGS[1])],
                XrefsTo=lambda ea, flags: [SimpleNamespace(frm={0x2000: 0x1104, 0x2100: 0x1124, 0x1100: 0x900}[ea])],
                Functions=lambda start=0, end=0xFFFFFFFF: sorted(ea for ea in self.functions if start <= ea < end),
                Chunks=lambda start: (
                    [(start, self.functions[start].end_ea)] + (self.owner_tails if start == self.owner_start else [])
                ),
            ),
            "idc": SimpleNamespace(print_insn_mnem=lambda ea: "call"),
        }

    def boundaries(self):
        return {ea: func.end_ea for ea, func in self.functions.items()}

    def get_func(self, ea):
        return next((func for func in self.functions.values() if func.start_ea <= ea < func.end_ea), None)

    def set_func_end(self, start, end):
        self.mutations.append(("set_end", start, end))
        if self.failure == "rollback" and end == 0x1300:
            return False
        self.functions[start].end_ea = end
        if self.failure == "truncate_exception" and end == 0x1100:
            raise RuntimeError("truncation failed after mutation")
        return True

    def add_func(self, start, end):
        self.mutations.append(("add", start, end))
        if self.failure in {"add", "rollback"}:
            return False
        self.functions[start] = SimpleNamespace(start_ea=start, end_ea=end)
        if self.failure == "add_exception":
            raise RuntimeError("add failed after mutation")
        return True

    def del_func(self, start):
        self.mutations.append(("delete", start))
        self.functions.pop(start)
        return True

    def auto_wait(self):
        if self.failure == "analysis_cancelled":
            return False
        if self.failure in {"boundary", "analysis_exception"}:
            self.functions[0x1100].end_ea = 0x1150
            self.functions[0x1200] = SimpleNamespace(start_ea=0x1200, end_ea=0x1300)
        if self.failure == "analysis_exception":
            raise RuntimeError("analysis failed after creating a remainder function")
        return True

    def execute(self, code):
        namespace = {}
        with patch.dict("sys.modules", self.modules):
            exec(code, namespace)
        return json.loads(namespace["result"])

    def locate(self):
        code = APP.LOCATE_PY.replace("ANCHOR_STRINGS_PLACEHOLDER", repr(APP.ANCHOR_STRINGS))
        code = code.replace("EXPECTED_ENTRY_PLACEHOLDER", "None")
        return self.execute(code)


class CGameBoundaryTests(unittest.TestCase):
    def test_contiguous_component_splits_at_exact_boundaries(self):
        idb = FakeIdb()
        result = idb.locate()
        self.assertNotIn("error", result)
        self.assertEqual("0x40", result["func_size"])
        self.assertEqual({0x1000: 0x1100, 0x1100: 0x1140}, idb.boundaries())

    def test_noncontiguous_merged_component_does_not_mutate_idb(self):
        idb = FakeIdb(gap=True)
        result = idb.locate()
        self.assertIn("error", result)
        self.assertEqual([], idb.mutations)
        self.assertEqual(idb.original, idb.boundaries())

    def test_existing_function_with_internal_gap_needs_no_split(self):
        idb = FakeIdb(gap=True, merged=False)
        result = idb.locate()
        self.assertNotIn("error", result)
        self.assertEqual([], idb.mutations)

    def test_failed_mutations_restore_original_boundaries(self):
        for failure in (
            "truncate_exception",
            "add",
            "add_exception",
            "boundary",
            "analysis_exception",
            "analysis_cancelled",
        ):
            with self.subTest(failure=failure):
                idb = FakeIdb(failure=failure, owner_tail=True)
                result = idb.locate()
                self.assertIn("error", result)
                self.assertEqual(idb.original, idb.boundaries())
                self.assertNotIn("rollback failed", result["error"])
                self.assertEqual([(0x1000, 0x1300), (0x1500, 0x1520)], list(idb.modules["idautils"].Chunks(0x1000)))

    def test_split_preserves_existing_constructor_tail(self):
        idb = FakeIdb(owner_tail=True)
        result = idb.locate()
        self.assertNotIn("error", result)
        self.assertEqual([(0x1000, 0x1100), (0x1500, 0x1520)], list(idb.modules["idautils"].Chunks(0x1000)))

    def test_rollback_failure_is_reported_explicitly(self):
        result = FakeIdb(failure="rollback").locate()
        self.assertIn("rollback", result["error"].lower())


class HostIncrementalTests(unittest.IsolatedAsyncioTestCase):
    async def run_host(self, idb, directory):
        async def inspect(session, ea, image_base, name, **kwargs):
            func = idb.get_func(ea)
            if name == "CGame_AppActivate" and (func is None or func.start_ea != ea):
                return None
            return {"func_va": hex(ea), "func_size": "0x40", "func_sig": "55 8B EC"}

        async def call_tool(tool, args):
            if "OWNER_EA =" in args["code"]:
                return {
                    "pointer_size": 4,
                    "gv_ea": "0x3000",
                    "insn_ea": "0x900",
                    "insn_len": "0x5",
                    "insn_disp": "0x1",
                }
            return idb.execute(args["code"])

        session = SimpleNamespace(call_tool=AsyncMock(side_effect=call_tool))
        with (
            patch("ida_preprocessor_scripts._direct_gv_common._inspect_function_via_mcp", side_effect=inspect),
            patch(
                "ida_preprocessor_scripts._direct_gv_common.gv_resolution_fields_via_mcp", AsyncMock(return_value={})
            ),
        ):
            result = await HOST.preprocess_skill(
                session,
                "find-SPR_Shutdown-host_initialized",
                [directory / "host_initialized.windows.yaml"],
                None,
                directory,
                "windows",
                0,
            )
        return result

    def write_inputs(self, directory, entry=0x1100):
        for name, ea in (("SPR_Shutdown", 0x900), ("CGame_AppActivate", entry)):
            (directory / f"{name}.windows.yaml").write_text(
                yaml.safe_dump({"func_name": name, "func_va": hex(ea), "func_sig": "55 8B EC"}), encoding="utf-8"
            )

    async def test_existing_artifact_and_fresh_merged_idb_can_generate_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_inputs(directory)
            original = (directory / "CGame_AppActivate.windows.yaml").read_bytes()
            idb = FakeIdb()
            self.assertTrue(await self.run_host(idb, directory))
            output = yaml.safe_load((directory / "host_initialized.windows.yaml").read_text())
            self.assertEqual("0x3000", output["gv_va"])
            self.assertEqual(original, (directory / "CGame_AppActivate.windows.yaml").read_bytes())
            self.assertEqual(0x1100, idb.get_func(0x1100).start_ea)

    async def test_stale_cross_artifact_does_not_split_a_different_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_inputs(directory, entry=0x1110)
            idb = FakeIdb()
            self.assertFalse(await self.run_host(idb, directory))
            self.assertEqual([], idb.mutations)
            self.assertFalse((directory / "host_initialized.windows.yaml").exists())

    async def test_failed_recovery_preserves_idb_and_does_not_write_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_inputs(directory)
            idb = FakeIdb(failure="add")
            self.assertFalse(await self.run_host(idb, directory))
            self.assertEqual(idb.original, idb.boundaries())
            self.assertFalse((directory / "host_initialized.windows.yaml").exists())

    async def test_existing_split_can_be_reused_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_inputs(directory)
            idb = FakeIdb(merged=False)
            self.assertTrue(await self.run_host(idb, directory))
            self.assertEqual([], idb.mutations)

    async def test_missing_cross_artifact_does_not_recover_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "SPR_Shutdown.windows.yaml").write_text(
                "func_name: SPR_Shutdown\nfunc_va: '0x900'\nfunc_sig: 55 8B EC\n", encoding="utf-8"
            )
            idb = FakeIdb()
            self.assertFalse(await self.run_host(idb, directory))
            self.assertEqual([], idb.mutations)
            self.assertFalse((directory / "host_initialized.windows.yaml").exists())

    async def test_noncontiguous_cross_component_does_not_recover_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_inputs(directory)
            idb = FakeIdb(gap=True)
            self.assertFalse(await self.run_host(idb, directory))
            self.assertEqual([], idb.mutations)
            self.assertFalse((directory / "host_initialized.windows.yaml").exists())
