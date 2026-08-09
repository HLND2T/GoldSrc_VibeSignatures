from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

import yaml

from analysis_planner import parse_config_document
from binary_format import inspect_binary

ROOT = Path(__file__).parents[1]
TAGS = {"cstrike-10120", "svencoop-10257"}
MODULES = {"engine", "client", "gameui", "server"}


class RepositoryContractTests(unittest.TestCase):
    def test_download_and_config_tags_match(self):
        downloads = yaml.safe_load((ROOT / "download.yaml").read_text(encoding="utf-8"))["downloads"]
        self.assertEqual(TAGS, {entry["tag"] for entry in downloads})
        self.assertEqual(TAGS, {path.stem for path in (ROOT / "configs").glob("*.yaml")})
        self.assertTrue(all("config" not in entry for entry in downloads))
        for entry in downloads:
            document = yaml.safe_load((ROOT / "configs" / f"{entry['tag']}.yaml").read_text(encoding="utf-8"))
            for module in document["modules"]:
                self.assertTrue(module["path_windows"].startswith(entry["basepath"] + "/"))
                self.assertTrue(module["path_linux"].startswith(entry["basepath"] + "/"))

    def test_production_configs_have_expected_modules_and_paths(self):
        for tag in TAGS:
            document = yaml.safe_load((ROOT / "configs" / f"{tag}.yaml").read_text(encoding="utf-8"))
            modules = parse_config_document(document)
            self.assertEqual(MODULES, {module["name"] for module in modules})
            for module in modules:
                self.assertTrue(module["path_windows"])
                self.assertTrue(module["path_linux"])

    def test_no_disallowed_runtime_subsystems_or_architecture_paths(self):
        disallowed = ("win64", "process_reporter_redis", "cpp_tests", "hl2sdk")
        checked = [path for path in ROOT.glob("*.py") if path.name not in {"format_repo_files.py"}]
        checked.extend((ROOT / "gamesymbol_snapshot_lib").glob("*.py"))
        for path in checked:
            text = path.read_text(encoding="utf-8").casefold()
            for marker in disallowed:
                self.assertNotIn(marker, text, f"{marker} remains in {path}")

    def test_documented_commands_and_ci_gate_match(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yaml").read_text(encoding="utf-8")
        commands = (
            "uv sync --locked",
            "uv run python format_repo_files.py --check",
            "uv run python tests/run_test_suite.py unit -b --durations 30",
            "uv run python tests/run_test_suite.py repository-contract -b --durations 30",
            "uv run python tests/run_test_suite.py all -b --durations 30",
        )
        for command in commands:
            self.assertIn(command, readme)
            self.assertIn(command, workflow)

    def test_sven_local_dlls_are_read_only_pe32_smoke_inputs(self):
        root = ROOT / "bin" / "svencoop"
        expected = {
            "client/client.dll",
            "engine/hw.dll",
            "gameui/GameUI.dll",
            "server/server.dll",
        }
        existing = {path.relative_to(root).as_posix() for path in root.glob("*/*.dll")} if root.is_dir() else set()
        if not existing:
            self.skipTest("Local Sven Co-op smoke binaries are not present")
        self.assertEqual(expected, existing)
        before = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in expected}
        self.assertEqual(
            {
                "client/client.dll": "f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6",
                "engine/hw.dll": "e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596",
                "gameui/GameUI.dll": "99382b87319d21139c0675d8a45669d64ef930f9e43dbd582461575383545f75",
                "server/server.dll": "f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0",
            },
            before,
        )
        for name in expected:
            info = inspect_binary(root / name)
            self.assertEqual(("PE", 32, "I386"), (info.container, info.bits, info.machine))
        after = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in expected}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
