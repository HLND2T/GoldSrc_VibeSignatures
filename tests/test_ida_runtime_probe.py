from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ida_runtime_probe import IdaRuntimeProbeError, query_ida_kernel_version, validate_same_installation


class IdaRuntimeProbeTests(unittest.TestCase):
    def test_accepts_idalib_mcp_beside_python_or_in_scripts_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "ida-python"
            scripts = root / "Scripts"
            scripts.mkdir(parents=True)
            python = root / "python.exe"
            sibling_mcp = root / "idalib-mcp.exe"
            scripts_mcp = scripts / "idalib-mcp.exe"
            for executable in (python, sibling_mcp, scripts_mcp):
                executable.write_bytes(b"executable")

            self.assertEqual(
                (python.resolve(), sibling_mcp.resolve()),
                validate_same_installation(python, sibling_mcp),
            )
            self.assertEqual(
                (python.resolve(), scripts_mcp.resolve()),
                validate_same_installation(python, scripts_mcp),
            )

    def test_rejects_python_and_idalib_mcp_from_different_installations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            python = root / "ida-a" / "python.exe"
            idalib_mcp = root / "ida-b" / "Scripts" / "idalib-mcp.exe"
            python.parent.mkdir(parents=True)
            idalib_mcp.parent.mkdir(parents=True)
            python.write_bytes(b"python")
            idalib_mcp.write_bytes(b"mcp")

            with self.assertRaisesRegex(IdaRuntimeProbeError, "different installations"):
                validate_same_installation(python, idalib_mcp)

    def test_queries_trimmed_kernel_version_after_initializing_idapro(self):
        imported = []
        idaapi = SimpleNamespace(get_kernel_version=Mock(return_value=" 9.3 \n"))

        def importer(name: str):
            imported.append(name)
            return SimpleNamespace() if name == "idapro" else idaapi

        self.assertEqual("9.3", query_ida_kernel_version(importer=importer))
        self.assertEqual(["idapro", "idaapi"], imported)

    def test_rejects_empty_kernel_version(self):
        def importer(name: str):
            if name == "idapro":
                return SimpleNamespace()
            return SimpleNamespace(get_kernel_version=lambda: "  ")

        with self.assertRaisesRegex(IdaRuntimeProbeError, "empty"):
            query_ida_kernel_version(importer=importer)


if __name__ == "__main__":
    unittest.main()
