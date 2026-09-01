from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from ida_analyze_util import canonical_symbol_yaml_bytes
from migrate_bin_artifacts import ArtifactMigrationError, migrate_bin_artifacts
from tests.test_support import write_config


class ArtifactMigrationTests(unittest.TestCase):
    def fixture(self, root: Path):
        configs = root / "configs"
        configs.mkdir()
        (configs / "config.yaml").write_text(
            yaml.safe_dump({"gamevers": ["game-1"]}, sort_keys=False), encoding="utf-8"
        )
        write_config(
            configs / "game-1.yaml",
            skill={"name": "find", "expected_output": ["symbol.{platform}.yaml"]},
        )
        module_dir = root / "bin" / "game-1" / "engine"
        module_dir.mkdir(parents=True)
        for platform, value in (("windows", "0x10"), ("linux", "0x20")):
            (module_dir / f"symbol.{platform}.yaml").write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "symbol", "func_va": value})
            )
        return module_dir

    def test_validates_then_copies_exact_bytes_idempotently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            self.assertEqual(2, migrate_bin_artifacts(root).files)
            self.assertFalse((root / "bin_artifacts").exists())
            self.assertEqual(2, migrate_bin_artifacts(root, write=True).files)
            self.assertEqual(
                (source / "symbol.windows.yaml").read_bytes(),
                (root / "bin_artifacts" / "game-1" / "engine" / "symbol.windows.yaml").read_bytes(),
            )
            self.assertEqual(2, migrate_bin_artifacts(root, write=True).files)

    def test_refuses_unknown_source_and_destination_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            (source / "unknown.yaml").write_text("bad: true\n", encoding="utf-8")
            with self.assertRaises(ArtifactMigrationError):
                migrate_bin_artifacts(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            migrate_bin_artifacts(root, write=True)
            destination = root / "bin_artifacts" / "game-1" / "engine" / "symbol.windows.yaml"
            destination.write_bytes(canonical_symbol_yaml_bytes({"func_name": "symbol", "func_va": "0x99"}))
            with self.assertRaises(ArtifactMigrationError):
                migrate_bin_artifacts(root, write=True)


if __name__ == "__main__":
    unittest.main()
