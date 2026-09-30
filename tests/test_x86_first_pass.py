"""First-iteration provenance must not accumulate unknown loop offsets."""

import unittest

from ida_preprocessor_scripts._x86_vcall_flow import first_pass_blocks, trace_function


class FirstPassTests(unittest.TestCase):
    def test_keeps_branches_but_removes_loop_backedge(self):
        blocks = [
            {"start": 10, "succs": [40], "insns": []},
            {"start": 40, "succs": [20, 50], "insns": []},
            {"start": 20, "succs": [30], "insns": []},
            {"start": 30, "succs": [40], "insns": []},
            {"start": 50, "succs": [], "insns": []},
        ]
        result = {b["start"]: b["succs"] for b in first_pass_blocks(blocks, 10)}
        self.assertEqual({10: [40], 40: [20, 50], 20: [30], 30: [], 50: []}, result)
        self.assertEqual([40], blocks[3]["succs"])

    def test_preserves_diamond_join(self):
        blocks = [
            {"start": ea, "succs": edges, "insns": []} for ea, edges in [(1, [2, 3]), (2, [4]), (3, [4]), (4, [])]
        ]
        self.assertEqual(blocks, first_pass_blocks(blocks, 1))

    def test_unknown_entry_fails_closed(self):
        with self.assertRaises(ValueError):
            first_pass_blocks([], 1)

    def test_first_iteration_keeps_pointer_argument_origin(self):
        def insn(ea, mnem, ops):
            return dict(ea=ea, mnem=mnem, ops=ops, sp=0, after=0)

        blocks = [
            dict(start=1, succs=[2], insns=[insn(1, "mov", [("reg", "esi"), ("mem", "esp", 4, None, 1, 4)])]),
            dict(start=2, succs=[3, 4], insns=[insn(2, "movzx", [("reg", "eax"), ("mem", "esi", 0, None, 1, 2)])]),
            dict(start=3, succs=[2], insns=[insn(3, "add", [("reg", "esi"), ("imm", 2)])]),
            dict(start=4, succs=[], insns=[]),
        ]
        full = trace_function(blocks, 1, "windows")
        first = trace_function(first_pass_blocks(blocks, 1), 1, "windows")
        self.assertIsNone(full["loads"][-1]["address"])
        self.assertEqual(("arg", 1), first["loads"][-1]["address"])


if __name__ == "__main__":
    unittest.main()
