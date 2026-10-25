"""Relational checks for native sparse row and item-ID accessors."""

import copy
import unittest

from ida_preprocessor_scripts._buildmode_identity import normalized, sparse_accessors


class SparseAccessorsTests(unittest.TestCase):
    def test_equivalent_shift_and_lea_scales_have_same_identity(self):
        row, base = ("arg", 1), ("load", ("arg", 0), 0x80)
        triple = ("indexed", row, row, 2)
        lea = ("indexed", base, triple, 4)
        shifted = ("indexed", base, ("indexed", ("const", 0), triple, 4), 1)
        self.assertEqual(normalized(lea), normalized(shifted))
        self.assertNotEqual(normalized(lea), normalized(("indexed", base, triple, 8)))

    @staticmethod
    def fixture(memory=0x84, count=0x98, data=0x50, panel_field=0, label_field=4):
        this, row = ("arg", 0), ("arg", 1)
        row_id = ("load", ("indexed", ("load", this, memory), row, 4), 0)

        def pointer(index, field):
            return ("load", ("load", ("indexed", ("load", this, data), index, 12), 0), field)

        def method(index, value, comparisons=()):
            return dict(
                index=index, flow=dict(returns=[dict(value=("const", 0)), dict(value=value)], comparisons=comparisons)
            )

        return [
            method(51, pointer(row_id, panel_field), [dict(values=[row, ("load", this, count)])]),
            method(93, pointer(row, panel_field)),
            method(17, pointer(row, label_field)),
        ]

    def test_matches_moved_slots_and_member_displacements(self):
        for fields in ((0x84, 0x98, 0x50, 0, 4), (0x130, 0x114, 0xAC, 8, 0)):
            with self.subTest(fields=fields):
                found = sparse_accessors(self.fixture(*fields))
                self.assertEqual(51, found["renderer"]["index"])
                self.assertEqual(93, found["panel"]["index"])
                self.assertEqual(17, found["label"]["index"])
                self.assertEqual({("load", ("arg", 0), fields[1])}, found["counts"])

    def test_rejects_unrelated_item_id_mapping(self):
        methods = self.fixture()
        methods[1] = self.fixture(data=0x54)[1]
        with self.assertRaisesRegex(ValueError, "expected one candidate"):
            sparse_accessors(methods)

    def test_requires_native_invalid_id_null_result(self):
        methods = self.fixture()
        methods[1]["flow"]["returns"].pop(0)
        with self.assertRaisesRegex(ValueError, "expected one candidate"):
            sparse_accessors(methods)

    def test_accepts_joined_null_and_valid_pointer_returns(self):
        methods = self.fixture()
        for method in methods:
            method["flow"]["returns"] = [dict(value=("choice", *(r["value"] for r in method["flow"]["returns"])))]
        self.assertEqual(93, sparse_accessors(methods)["panel"]["index"])

    def test_rejects_ambiguous_label_getter(self):
        methods = self.fixture()
        methods.append(copy.deepcopy(methods[-1]))
        methods[-1]["index"] = 21
        with self.assertRaisesRegex(ValueError, "expected one candidate"):
            sparse_accessors(methods)

    def test_requires_row_bounds(self):
        methods = self.fixture()
        methods[0]["flow"]["comparisons"] = []
        with self.assertRaisesRegex(ValueError, "expected one candidate"):
            sparse_accessors(methods)


if __name__ == "__main__":
    unittest.main()
