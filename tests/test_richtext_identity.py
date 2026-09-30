"""Reject superficially similar guards lacking character or side-effect evidence."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _gameui_richtext_common as common
from ida_preprocessor_scripts._richtext_identity import character_guard, pointer_increment


def fixture(wide=False, inverted=False):
    arg = ("arg", 1)
    this = ("arg", 0)
    flow = dict(
        comparisons=[dict(ea=10, block=10, values=[("narrow", ("load", arg, 0) if wide else arg, 1), ("const", 13)])],
        stores=[dict(ea=21, address=("address", this, 80), value=("address", ("load", this, 64), -2), width=4)],
        calls=[dict(ea=22, block=20, args=[this], target=("load", ("load", this, 0), 16), direct=None)],
    )
    blocks = [
        dict(
            start=10,
            succs=[20, 30],
            insns=[
                dict(ea=10, mnem="cmp"),
                dict(ea=11, mnem="mov"),
                dict(ea=12, mnem="jnz" if inverted else "jz", branch=20 if inverted else 30),
            ],
        ),
        dict(start=20, succs=[30], insns=[dict(ea=21, mnem="mov"), dict(ea=22, mnem="call")]),
        dict(start=30, succs=[10] if wide else [], insns=[dict(ea=30, mnem="jmp" if wide else "retn")]),
    ]
    return flow, blocks


class CharacterGuardTests(unittest.TestCase):
    def test_pointer_increment_accepts_add_and_equivalent_lea(self):
        register = ("reg", "esi", 4)
        self.assertTrue(pointer_increment("add", [register, ("imm", 2)], 2))
        self.assertTrue(pointer_increment("lea", [register, ("mem", "esi", 2, None, 1, 4)], 2))
        self.assertFalse(pointer_increment("lea", [register, ("mem", "edi", 2, None, 1, 4)], 2))
        self.assertFalse(pointer_increment("lea", [register, ("mem", "esi", 2, "eax", 1, 4)], 2))
        self.assertFalse(pointer_increment("add", [register, ("imm", 2)], 4))

    def test_accepts_scalar_and_inlined_loop_with_both_branch_directions(self):
        for wide in (False, True):
            for inverted in (False, True):
                with self.subTest(wide=wide, inverted=inverted):
                    result = character_guard(*fixture(wide, inverted), wide)
                    self.assertEqual((12, 20, 30), (result["branch"], result["work"], result["skip"]))

    def test_rejects_string_load_as_scalar_character(self):
        with self.assertRaises(ValueError):
            character_guard(*fixture(True), False)

    def test_rejects_flags_clobber_between_comparison_and_jump(self):
        flow, blocks = fixture()
        blocks[0]["insns"][1]["mnem"] = "add"
        with self.assertRaises(ValueError):
            character_guard(flow, blocks, False)

    def test_rejects_guard_that_does_not_skip_linebreak_update(self):
        flow, blocks = fixture()
        blocks[2]["succs"] = [20]
        with self.assertRaises(ValueError):
            character_guard(flow, blocks, False)

    def test_rejects_unrelated_counter_or_repaint_receiver(self):
        for change in ("count", "receiver"):
            flow, blocks = fixture()
            if change == "count":
                flow["stores"][0]["value"] = ("const", 2)
            else:
                flow["calls"][0]["args"] = [("arg", 1)]
            with self.subTest(change=change), self.assertRaises(ValueError):
                character_guard(flow, blocks, False)

    def test_rejects_duplicate_guard_evidence(self):
        flow, blocks = fixture()
        flow["comparisons"].append(copy.deepcopy(flow["comparisons"][0]))
        with self.assertRaises(ValueError):
            character_guard(flow, blocks, False)


class CalleePublicationTests(unittest.IsolatedAsyncioTestCase):
    async def test_transport_failure_removes_unvalidated_intermediate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "Owner.windows.yaml").write_text("func_va: '0x1000'\n", encoding="utf-8")
            output = directory / f"{common.WIDE}.windows.yaml"

            async def generate(**kwargs):
                output.write_text("func_va: '0x2000'\n", encoding="utf-8")
                return True

            with (
                patch.object(common, "preprocess_common_skill", side_effect=generate),
                patch.object(common, "walk", new=AsyncMock(side_effect=ConnectionError("worker disconnected"))),
            ):
                found = await common.recover_callee(
                    None, [output], directory, "windows", 0, "Owner", common.WIDE, "reference.yaml", None, False
                )
            self.assertFalse(found)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
