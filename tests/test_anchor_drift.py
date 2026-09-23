from __future__ import annotations

import unittest

import yaml

from gamesymbol_snapshot_lib.anchor_drift import anchor_only_drift
from ida_analyze_util import canonical_symbol_yaml_bytes

# Each fixture carries the category's full optional field matrix -- anchor
# fields and policy switches alike -- so a subtest can mutate one value in place
# instead of adding a key, which would be rejected as a resized payload.
GV_PAYLOAD = {
    "gv_name": "gWorldToScreen",
    "gv_va": "0x2c20100",
    "gv_rva": "0xf20100",
    "gv_sig": "55 8B EC 83 E4 F8 83 EC 10 53 55 56 57 68 01 17 00 00",
    "gv_sig_va": "0x1d46430",
    "gv_inst_offset": "0x8",
    "gv_inst_length": "0x5",
    "gv_inst_disp": "0x1",
    "gv_pic_addend": "0x10",
    "gv_address_offset": "0x10",
    "gv_sig_allow_across_function_boundary": True,
}

STRUCT_PAYLOAD = {
    "struct_name": "CVideoMode_Common",
    "member_name": "m_ImageID.m_Size",
    "offset": "0x1a8",
    "size": "4",
    "offset_sig": "55 8B EC 83 EC 48 89 4D ?? 8B 4D ?? 81 C1 9C 01 00 00 E8 ?? ?? ?? ?? 85 C0 75 ??",
    "offset_sig_disp": "0xc",
    "offset_sig_ref_kind": "immediate",
    "offset_sig_addend": "0xc",
    "offset_sig_max_match": 1,
}

VFUNC_PAYLOAD = {
    "func_name": "GameStudioRenderer_StudioCalcAttachments",
    "func_va": "0x1008bd20",
    "func_rva": "0x8bd20",
    "func_size": "0xa1",
    "func_sig": "55 8B EC 51 53 56 8B F1 57 8B 46 ?? 8B 88 ?? ?? ?? ?? 83 F9 04 7F ??",
    "vtable_name": "GameStudioRenderer",
    "vfunc_offset": "0x1c",
    "vfunc_index": 7,
    "vfunc_sig": "55 8B EC 51 53 56 8B F1 57 8B 46 ?? 8B 88 ?? ?? ?? ?? 83 F9 04 7F ??",
    "vfunc_sig_disp": "0x10",
    "vfunc_sig_max_match": 1,
    "vfunc_sig_allow_across_function_boundary": True,
}

FUNC_PAYLOAD = {
    "func_name": "R_DrawSequentialPoly",
    "func_va": "0x1000",
    "func_rva": "0x1000",
    "func_sig": "55 8B EC 83 EC 10",
}

PATCH_PAYLOAD = {
    "patch_name": "cl_enginefuncs_table",
    "patch_va": "0x2000",
    "patch_rva": "0x2000",
    "patch_sig": "90 90 90 90",
}


def canonical(payload: dict) -> bytes:
    return canonical_symbol_yaml_bytes(payload)


class AnchorOnlyDriftTests(unittest.TestCase):
    NUMERIC_ANCHOR_CASES = (
        (
            GV_PAYLOAD,
            ("gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp", "gv_pic_addend", "gv_address_offset"),
        ),
        (STRUCT_PAYLOAD, ("offset_sig_disp", "offset_sig_addend")),
        (VFUNC_PAYLOAD, ("vfunc_sig_disp",)),
    )

    def test_invalid_numeric_anchor_fails_closed(self):
        for payload, fields in self.NUMERIC_ANCHOR_CASES:
            expected = canonical(payload)
            for field in fields:
                for value in (None, True, -1, "", "not-an-offset", "-0x1"):
                    with self.subTest(field=field, value=value):
                        actual = yaml.safe_dump({**payload, field: value}).encode("utf-8")
                        self.assertIsNone(anchor_only_drift(expected, actual))
                        self.assertIsNone(anchor_only_drift(actual, expected))

    def test_unchanged_null_numeric_anchor_with_signature_drift_fails_closed(self):
        for payload, fields in self.NUMERIC_ANCHOR_CASES:
            signature = next(key for key in payload if key in {"gv_sig", "offset_sig", "vfunc_sig"})
            for field in fields:
                with self.subTest(field=field):
                    self.assert_drift({**payload, field: None}, {signature: "90 90"}, accepted=False)

    def test_optional_numeric_anchor_fields_can_be_omitted(self):
        for payload, fields, signature in (
            (GV_PAYLOAD, ("gv_inst_disp", "gv_pic_addend", "gv_address_offset"), "gv_sig"),
            (STRUCT_PAYLOAD, ("offset_sig_disp", "offset_sig_addend"), "offset_sig"),
            (VFUNC_PAYLOAD, ("vfunc_sig_disp",), "vfunc_sig"),
        ):
            with self.subTest(signature=signature):
                self.assert_drift(
                    {key: value for key, value in payload.items() if key not in fields},
                    {signature: "90 90"},
                    accepted=True,
                )

    def test_zero_numeric_anchor_fields_are_valid(self):
        for payload, fields in self.NUMERIC_ANCHOR_CASES:
            for field in fields:
                if field == "gv_inst_length":
                    continue
                with self.subTest(field=field):
                    self.assert_drift(payload, {field: "0x0"}, accepted=True)

    def assert_drift(self, payload: dict, overrides: dict, accepted: bool) -> None:
        expected = canonical(payload)
        actual = canonical({**payload, **overrides})
        self.assertNotEqual(expected, actual)
        changed = anchor_only_drift(expected, actual)
        if accepted:
            self.assertEqual(set(overrides), set(changed or {}))
        else:
            self.assertIsNone(changed)

    def test_global_anchor_fields_drift(self):
        for field, value in (
            ("gv_sig", "55 8B EC 83 E4 F8 83 EC 10 53 55 56 57 68 02 17 00 00"),
            ("gv_sig_va", "0x1d46470"),
            ("gv_inst_offset", "0xc"),
            ("gv_inst_length", "0x6"),
            ("gv_inst_disp", "0x2"),
            ("gv_pic_addend", "0x20"),
            ("gv_address_offset", "0x20"),
        ):
            with self.subTest(field=field):
                self.assert_drift(GV_PAYLOAD, {field: value}, accepted=True)

    def test_global_resolved_facts_and_policy_stay_pinned(self):
        for overrides in (
            {"gv_va": "0x2c20200", "gv_rva": "0xf20200"},
            {"gv_name": "gOtherToScreen"},
            {"gv_sig_allow_across_function_boundary": False},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(GV_PAYLOAD, overrides, accepted=False)

    def test_incoherent_global_anchor_fails_closed(self):
        # The displacement operand must stay inside the anchored instruction.
        self.assert_drift(
            {**GV_PAYLOAD, "gv_inst_offset": "0xc"},
            {"gv_inst_disp": "0x7"},
            accepted=False,
        )

    def test_struct_member_anchor_fields_drift(self):
        for field, value in (
            ("offset_sig", "55 8B EC 83 EC 48 89 4D ?? 8B 4D ?? 81 C1 A0 01 00 00 E8 ?? ?? ?? ?? 85 C0 75 ??"),
            ("offset_sig_disp", "0x10"),
            ("offset_sig_addend", "0x10"),
            ("offset_sig_ref_kind", "displacement"),
        ):
            with self.subTest(field=field):
                self.assert_drift(STRUCT_PAYLOAD, {field: value}, accepted=True)

    def test_struct_member_resolved_facts_and_policy_stay_pinned(self):
        for overrides in (
            {"offset": "0x1b4"},
            {"size": "8"},
            {"struct_name": "CVideoMode_GL"},
            {"offset_sig_max_match": 2},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(STRUCT_PAYLOAD, overrides, accepted=False)

    def test_vfunc_anchor_fields_drift(self):
        for field, value in (
            ("vfunc_sig", "55 8B EC 51 53 56 8B F1 57 8B 46 ?? 8B 88 ?? ?? ?? ?? 83 F9 05 7F ??"),
            ("vfunc_sig_disp", "0x20"),
        ):
            with self.subTest(field=field):
                self.assert_drift(VFUNC_PAYLOAD, {field: value}, accepted=True)

    def test_vfunc_resolved_facts_and_policy_stay_pinned(self):
        for overrides in (
            {"vfunc_offset": "0x20", "vfunc_index": 8},
            {"func_va": "0x1008bd30", "func_rva": "0x8bd30"},
            {"func_sig": "55 8B EC 51 53 56 8B F1 57 8B 46 ?? 8B 88 ?? ?? ?? ?? 83 F9 05 7F ??"},
            {"vfunc_sig_max_match": 2},
            {"vfunc_sig_allow_across_function_boundary": False},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(VFUNC_PAYLOAD, overrides, accepted=False)

    def test_categories_without_an_anchor_spec_stay_byte_exact(self):
        for payload, overrides in (
            (FUNC_PAYLOAD, {"func_sig": "55 8B EC 83 EC 20"}),
            (PATCH_PAYLOAD, {"patch_sig": "90 90 CC CC"}),
        ):
            with self.subTest(payload=payload):
                self.assert_drift(payload, overrides, accepted=False)

    def test_resized_payload_fails_closed(self):
        expected = canonical(VFUNC_PAYLOAD)
        actual = canonical({k: v for k, v in VFUNC_PAYLOAD.items() if k != "vfunc_sig_disp"})
        self.assertIsNone(anchor_only_drift(expected, actual))

    def test_unparseable_payload_fails_closed(self):
        expected = canonical(GV_PAYLOAD)
        for actual in (b"\xff\n", b"- 1\n", b"gv_name: [unclosed\n"):
            with self.subTest(actual=actual):
                self.assertIsNone(anchor_only_drift(expected, actual))

    def test_identical_payload_is_not_drift(self):
        expected = canonical(GV_PAYLOAD)
        self.assertIsNone(anchor_only_drift(expected, expected))


if __name__ == "__main__":
    unittest.main()
