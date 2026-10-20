"""Synthetic instruction, capacity and coverage regressions for storage locators."""

import unittest

from ida_preprocessor_scripts._career_storage_identity import (
    branch_strategy,
    checked_capacity,
    unique,
    validate_groups,
)


class StorageBoundaryTests(unittest.TestCase):
    def test_direct_and_import_calls_redirect(self):
        for raw in (b"\xe8\x12\x34\x56\x78", b"\xff\x15\x12\x34\x56\x78"):
            self.assertEqual(branch_strategy(raw, "format"), 0)

    def test_short_indirect_calls_require_their_verified_hook_mechanism(self):
        self.assertEqual(branch_strategy(b"\xff\x52\x28", "enumeration_open"), 1)
        self.assertEqual(branch_strategy(b"\xff\xd0", "resume_name_set"), 2)
        for raw in (b"\xff\x52\x28", b"\xff\xd0"):
            with self.assertRaises(ValueError):
                branch_strategy(raw, "format")

    def test_jump_and_non_calls_are_rejected(self):
        for raw in (b"\xe9\x00\x00\x00\x00", b"\xff\xe0", b"\x8b\x80\xe4\x01\x00\x00"):
            with self.assertRaises(ValueError):
                branch_strategy(raw, "resume_name_set")

    def test_long_virtual_call_has_sufficient_space(self):
        self.assertEqual(branch_strategy(b"\xff\x90\xe4\x01\x00\x00", "resume_name_set"), 0)

    def test_explicit_limit_is_bounded_by_actual_stack_storage(self):
        self.assertEqual(checked_capacity(-280, -20), 260)
        self.assertEqual(checked_capacity(-84, -20, 62), 62)
        for explicit in (0, 65, -1, True):
            with self.assertRaises(ValueError):
                checked_capacity(-84, -20, explicit)

    def test_ambiguity_and_missing_results_fail_closed(self):
        for items in ([], [1, 2]):
            with self.assertRaises(ValueError):
                unique(items, "owner")

    def test_inline_copies_cannot_be_dropped(self):
        sites = {"copy": [{"ea": 10}, {"ea": 30}]}
        validate_groups(sites, {"copy": [0, 1]})
        for declared in ({"copy": [0]}, {"copy": [0, 2]}, {}):
            with self.assertRaises(ValueError):
                validate_groups(sites, declared)

    def test_one_callsite_cannot_have_two_owners(self):
        with self.assertRaises(ValueError):
            validate_groups({"a": [{"ea": 10}], "b": [{"ea": 10}]}, {"a": [0], "b": [0]})


if __name__ == "__main__":
    unittest.main()
