import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ida_preprocessor_scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIRECT_GV = load_module("_direct_gv_common")


class InspectOwnerArtifactTests(unittest.IsolatedAsyncioTestCase):
    """Owner artifacts may store a source-qualified func_name identity."""

    FUNC_VA = 0x1000
    FUNC_SIZE = 0x40

    def write_artifact(self, directory, stem, func_name):
        (directory / f"{stem}.windows.yaml").write_text(
            yaml.safe_dump(
                {
                    "func_name": func_name,
                    "func_va": hex(self.FUNC_VA),
                    "func_rva": hex(self.FUNC_VA),
                    "func_size": hex(self.FUNC_SIZE),
                    "func_sig": "55 8B EC",
                }
            ),
            encoding="utf-8",
        )

    async def inspect(self, directory, owner_name, **kwargs):
        async def call_tool(tool, args):
            self.assertEqual("py_eval", tool)
            return {"pointer_size": 4, "is_function_start": True, "image_base": "0x0"}

        session = SimpleNamespace(call_tool=AsyncMock(side_effect=call_tool))
        function = {"func_va": hex(self.FUNC_VA), "func_size": hex(self.FUNC_SIZE), "func_sig": "55 8B EC"}
        with patch.object(DIRECT_GV, "_inspect_function_via_mcp", AsyncMock(return_value=function)):
            return await DIRECT_GV.inspect_owner_artifact(session, directory, "windows", 0, owner_name, **kwargs)

    async def test_source_qualified_identity_needs_the_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_artifact(directory, "EngineSurface_drawFlushText", "EngineSurface::drawFlushText()")
            self.assertIsNone(await self.inspect(directory, "EngineSurface_drawFlushText"))
            owner = await self.inspect(
                directory, "EngineSurface_drawFlushText", func_name="EngineSurface::drawFlushText()"
            )
            self.assertIsNotNone(owner)
            self.assertEqual(self.FUNC_VA, owner["owner_ea"])
            self.assertEqual(self.FUNC_VA + self.FUNC_SIZE, owner["owner_end"])

    async def test_stem_identity_keeps_resolving_without_the_override(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_artifact(directory, "GL_Bind", "GL_Bind")
            owner = await self.inspect(directory, "GL_Bind")
            self.assertIsNotNone(owner)
            self.assertEqual(self.FUNC_VA, owner["owner_ea"])

    async def test_mismatched_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_artifact(directory, "EngineSurface_drawFlushText", "EngineSurface::drawFlushText()")
            self.assertIsNone(
                await self.inspect(directory, "EngineSurface_drawFlushText", func_name="EngineSurface::drawFlushText")
            )

    async def test_missing_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(await self.inspect(Path(temporary), "EngineSurface_drawFlushText"))


if __name__ == "__main__":
    unittest.main()
