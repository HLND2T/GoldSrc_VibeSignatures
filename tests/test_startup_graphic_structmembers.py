import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "startup_graphic", ROOT / "ida_preprocessor_scripts/find-CVideoMode_Common_DrawStartupGraphic-structmembers.py"
)
FINDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINDER)


class StartupGraphicStructMembersTests(unittest.IsolatedAsyncioTestCase):
    async def run_preprocessor(
        self, root, *, member="m_ImageID.m_Size", struct="CVideoMode_Common", size_offset="0x328"
    ):
        outputs = [root / f"{name}.windows.yaml" for name in FINDER.MEMBER_NAMES]
        offsets = ["0x31c", size_offset, "0x330", "0x334"]

        async def emit_outputs(**kwargs):
            for output, name, offset in zip(outputs, FINDER.MEMBER_NAMES, offsets):
                payload = {
                    "struct_name": struct if name == FINDER.SIZE_SYMBOL else "CVideoMode_Common",
                    "member_name": member if name == FINDER.SIZE_SYMBOL else FINDER.MEMBER_BY_SYMBOL[name],
                    "offset": offset,
                    "size": "4",
                    "offset_sig": "55 8B EC",
                    "offset_sig_disp": "0x2d",
                }
                output.write_text(yaml.safe_dump(payload), encoding="utf-8")
            return True

        owner = {"owner_ea": 0x1000, "artifact": {"func_sig": "55 8B EC"}}
        with (
            patch.object(FINDER, "inspect_owner_artifact", AsyncMock(return_value=owner)),
            patch.object(FINDER, "_find_unique_bytes", AsyncMock(return_value=0x1000)),
            patch.object(FINDER, "_fallback_candidate", AsyncMock(return_value=(None, True))),
            patch.object(FINDER, "preprocess_common_skill", side_effect=emit_outputs),
        ):
            result = await FINDER.preprocess_skill(
                None,
                "find-CVideoMode_Common_DrawStartupGraphic-structmembers",
                outputs,
                None,
                str(root),
                "windows",
                0,
            )
        return result, outputs

    async def test_nested_member_alias_is_canonicalized(self):
        for member in ("m_ImageID_m_Size", "m_ImageID.m_Size"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                result, outputs = await self.run_preprocessor(Path(directory), member=member)
                self.assertTrue(result)
                payload = yaml.safe_load(outputs[1].read_text(encoding="utf-8"))
                self.assertEqual("m_ImageID.m_Size", payload["member_name"])
                self.assertEqual("0x328", payload["offset"])
                self.assertEqual("55 8B EC", payload["offset_sig"])
                self.assertEqual("0x2d", payload["offset_sig_disp"])

    async def test_invalid_identity_or_layout_fails_and_removes_outputs(self):
        for invalid in (
            {"member": "m_ImageID_m_Capacity"},
            {"struct": "OtherVideoMode"},
            {"member": "m_ImageID_m_Size", "size_offset": "0x32c"},
        ):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as directory:
                result, outputs = await self.run_preprocessor(Path(directory), **invalid)
                self.assertFalse(result)
                self.assertFalse(any(output.exists() for output in outputs))


if __name__ == "__main__":
    unittest.main()
