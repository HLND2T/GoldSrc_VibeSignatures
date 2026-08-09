from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import copy_depot_bin
import download_depot
from analysis_config import AnalysisConfigError, default_analysis_config_path, validated_tag
from tests.test_support import write_config, write_pe32


class TagAndConfigTests(unittest.TestCase):
    def test_accepts_safe_release_tag(self):
        self.assertEqual("cstrike-10120", validated_tag("cstrike-10120"))
        self.assertEqual("game-mod-123", validated_tag("game-mod-123"))

    def test_rejects_unsafe_or_unversioned_tags(self):
        for value in ("cstrike", "CStrike-1", "../game-1", "game-latest", "game_1"):
            with self.subTest(value=value), self.assertRaises(AnalysisConfigError):
                validated_tag(value)

    def test_default_config_is_tag_named(self):
        with tempfile.TemporaryDirectory() as temporary:
            expected = Path(temporary).resolve() / "configs" / "svencoop-10257.yaml"
            self.assertEqual(expected, default_analysis_config_path("svencoop-10257", repo_root=Path(temporary)))


class DownloadConfigTests(unittest.TestCase):
    def test_auth_arguments_default_to_environment_variables(self):
        with patch.dict(
            "os.environ",
            {
                "DEPOTDOWNLOADER_STEAM_USERNAME": "env-user",
                "DEPOTDOWNLOADER_STEAM_PASSWORD": "env-secret",
            },
            clear=False,
        ):
            args = download_depot.parse_args(["-tag", "cstrike-10120"])
        self.assertEqual("env-user", args.username)
        self.assertEqual("env-secret", args.password)

    def test_auth_arguments_override_environment_variables(self):
        with patch.dict(
            "os.environ",
            {
                "DEPOTDOWNLOADER_STEAM_USERNAME": "env-user",
                "DEPOTDOWNLOADER_STEAM_PASSWORD": "env-secret",
            },
            clear=False,
        ):
            args = download_depot.parse_args(
                [
                    "-tag",
                    "cstrike-10120",
                    "-username",
                    "cli-user",
                    "-password",
                    "cli-secret",
                ]
            )
        self.assertEqual("cli-user", args.username)
        self.assertEqual("cli-secret", args.password)

    def test_production_downloads_have_exact_apps_and_manifests(self):
        entries = download_depot.load_downloads(Path(__file__).parents[1] / "download.yaml")
        by_tag = {entry["tag"]: entry for entry in entries}
        self.assertEqual(10, by_tag["cstrike-10120"]["appid"])
        self.assertEqual({"2", "8"}, set(by_tag["cstrike-10120"]["manifests"]))
        self.assertEqual(225840, by_tag["svencoop-10257"]["appid"])
        self.assertEqual("Sven-Coop", by_tag["svencoop-10257"]["basepath"])
        self.assertNotIn("config", by_tag["svencoop-10257"])

    def test_major_update_must_be_boolean_when_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "download.yaml"
            path.write_text(
                """downloads:
  - tag: game-1
    appid: 1
    basepath: Game
    major_update: invalid
    manifests:
      '1': '1'
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(download_depot.ConfigError, "major_update"):
                download_depot.load_downloads(path)

    def test_filelist_collects_both_platforms(self):
        root = Path(__file__).parents[1]
        paths = download_depot.load_module_filelist(root / "configs" / "cstrike-10120.yaml")
        self.assertIn("Half-Life/hw.dll", paths)
        self.assertIn("Half-Life/hw.so", paths)
        self.assertEqual(len(paths), len(set(paths)))

    def test_depotdownloader_command_uses_entry_appid_and_manifest(self):
        command = download_depot.build_depotdownloader_command(
            appid=10,
            depot="2",
            manifest="123",
            depot_dir="depots",
            os_name="all-platform",
            filelist_path="files.txt",
            username="user",
            password="secret",
            remember_password=True,
        )
        self.assertEqual("10", command[command.index("-app") + 1])
        self.assertEqual("2", command[command.index("-depot") + 1])
        self.assertEqual("123", command[command.index("-manifest") + 1])
        self.assertIn("-remember-password", command)


class CopyDepotTests(unittest.TestCase):
    def test_copy_and_checkonly_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = write_config(root / "config.yaml", both_platforms=False)
            source = write_pe32(root / "depots" / "Game" / "hw.dll")
            self.assertTrue(source.is_file())
            args = [
                "-gamever",
                "game-1",
                "-config",
                str(config),
                "-depotdir",
                str(root / "depots"),
                "-bindir",
                str(root / "bin"),
                "-platform",
                "windows",
            ]
            self.assertEqual(1, copy_depot_bin.main([*args, "-checkonly"]))
            self.assertEqual(0, copy_depot_bin.main(args))
            self.assertEqual(0, copy_depot_bin.main([*args, "-checkonly"]))

    def test_checkonly_configuration_error_is_two(self):
        self.assertEqual(
            2,
            copy_depot_bin.main(["-gamever", "unsafe", "-config", "missing.yaml", "-checkonly"]),
        )

    def test_parse_config_rejects_case_collision(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {"name": "Engine", "path_windows": "Game/a.dll"},
                            {"name": "engine", "path_windows": "Game/b.dll"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises((TypeError, ValueError)):
                copy_depot_bin.parse_config(path)


if __name__ == "__main__":
    unittest.main()
