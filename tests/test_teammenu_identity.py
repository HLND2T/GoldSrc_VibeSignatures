import copy
import unittest

from ida_preprocessor_scripts._teammenu_identity import classify_map_owner, LOAD_MAP_NAME, UPDATE_NAME


class TeamMenuIdentityTests(unittest.TestCase):
    def flow(self):
        return {
            "blocks": {10: [20, 50], 20: [30, 50], 30: [50], 50: []},
            "branches": [
                {"condition": ("arg", 3), "nonzero": 20, "zero": 50},
                {"condition": ("load", ("arg", 3), 0), "nonzero": 30, "zero": 50},
            ],
            "calls": [{"block": 30, "direct": 123, "args": [("arg", 0), ("arg", 3), ("arg", 4)]}],
        }

    def test_standalone_and_inlined_have_distinct_identities(self):
        self.assertEqual(("TeamMenu_LoadMapPage", LOAD_MAP_NAME), classify_map_owner("windows", "", [4], {}, set()))
        self.assertEqual(("TeamMenu_Update", UPDATE_NAME), classify_map_owner("windows", "", [16], self.flow(), {123}))
        self.assertEqual(
            ("TeamMenu_LoadMapPage", LOAD_MAP_NAME),
            classify_map_owner("linux", "_ZN9CTeamMenu11LoadMapPageEPKc", [0], {}, set()),
        )

    def test_cleanup_alone_cannot_identify_update(self):
        for flow, targets in [({}, {123}), (self.flow(), {124})]:
            with self.assertRaises(ValueError):
                classify_map_owner("windows", "", [16], flow, targets)

    def test_arguments_and_null_guards_are_required(self):
        for index in range(3):
            flow = self.flow()
            flow["calls"][0]["args"][index] = ("const", 0)
            with self.assertRaises(ValueError):
                classify_map_owner("windows", "", [16], flow, {123})
        for index in range(2):
            flow = self.flow()
            flow["branches"][index]["zero"] = 30
            with self.assertRaises(ValueError):
                classify_map_owner("windows", "", [16], flow, {123})

    def test_conflicting_cleanup_or_symbol_is_rejected(self):
        for cleanups in ([4], [4, 16], [0], []):
            with self.assertRaises(ValueError):
                classify_map_owner("windows", "", cleanups, self.flow(), {123})
        with self.assertRaises(ValueError):
            classify_map_owner("linux", "_ZN9CTeamMenu11LoadMapPageEPKc", [0], self.flow(), {123})

    def test_duplicate_forwarding_is_ambiguous(self):
        flow = self.flow()
        flow["calls"].append(copy.deepcopy(flow["calls"][0]))
        with self.assertRaises(ValueError):
            classify_map_owner("windows", "", [16], flow, {123})
        with self.assertRaises(ValueError):
            classify_map_owner("windows", "", [4], flow, {123})
