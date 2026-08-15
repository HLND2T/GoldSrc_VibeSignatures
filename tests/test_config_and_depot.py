from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import copy_depot_bin
import download_depot
from analysis_config import (
    AnalysisConfigError,
    default_analysis_config_path,
    iter_analysis_config_tags,
    validated_tag,
)
from tests.test_support import write_config, write_pe32


class TagAndConfigTests(unittest.TestCase):
    def test_accepts_safe_release_tag(self):
        self.assertEqual("cstrike-10210", validated_tag("cstrike-10210"))
        self.assertEqual("game-mod-123", validated_tag("game-mod-123"))

    def test_rejects_unsafe_or_unversioned_tags(self):
        for value in ("cstrike", "CStrike-1", "../game-1", "game-latest", "game_1"):
            with self.subTest(value=value), self.assertRaises(AnalysisConfigError):
                validated_tag(value)

    def test_default_config_is_tag_named(self):
        with tempfile.TemporaryDirectory() as temporary:
            expected = Path(temporary).resolve() / "configs" / "svencoop-10257.yaml"
            self.assertEqual(expected, default_analysis_config_path("svencoop-10257", repo_root=Path(temporary)))

    def test_iter_tags_follows_manifest_order_then_lexical_orphans(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configs = root / "configs"
            configs.mkdir()
            (root / "download.yaml").write_text(
                "downloads:\n  - tag: hl-10210\n  - tag: hl-8684\n",
                encoding="utf-8",
            )
            for tag in ("hl-8684", "hl-10210", "cof-5936"):
                (configs / f"{tag}.yaml").write_text("modules: []\n", encoding="utf-8")
            self.assertEqual(
                ["hl-10210", "hl-8684", "cof-5936"],
                iter_analysis_config_tags(repo_root=root),
            )

    def test_iter_tags_rejects_invalid_filenames(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configs = root / "configs"
            configs.mkdir()
            (configs / "hl-10210.yaml").write_text("modules: []\n", encoding="utf-8")
            (configs / "not-a-tag.yaml").write_text("modules: []\n", encoding="utf-8")
            with self.assertRaises(AnalysisConfigError):
                iter_analysis_config_tags(repo_root=root)

    def test_iter_tags_empty_without_configs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "configs").mkdir()
            self.assertEqual([], iter_analysis_config_tags(repo_root=root))


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
            args = download_depot.parse_args(["-tag", "cstrike-10210"])
        self.assertEqual("env-user", args.username)
        self.assertEqual("env-secret", args.password)
        self.assertTrue(args.remember_password)

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
                    "cstrike-10210",
                    "-username",
                    "cli-user",
                    "-password",
                    "cli-secret",
                ]
            )
        self.assertEqual("cli-user", args.username)
        self.assertEqual("cli-secret", args.password)
        self.assertTrue(args.remember_password)

    def test_production_downloads_have_exact_apps_and_manifests(self):
        entries = download_depot.load_downloads(Path(__file__).parents[1] / "download.yaml")
        by_tag = {entry["tag"]: entry for entry in entries}
        self.assertEqual(70, by_tag["hl-10210"]["appid"])
        self.assertEqual({"2", "8", "71"}, set(by_tag["hl-10210"]["manifests"]))
        self.assertEqual(10, by_tag["cstrike-10210"]["appid"])
        self.assertEqual({"11"}, set(by_tag["cstrike-10210"]["manifests"]))
        self.assertEqual(225840, by_tag["svencoop-10257"]["appid"])
        self.assertEqual("Sven-Coop-10257", by_tag["svencoop-10257"]["basepath"])
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

    def test_filelist_collects_both_platforms_relative_to_depot_root(self):
        root = Path(__file__).parents[1]
        paths = download_depot.load_module_filelist(root / "configs" / "cstrike-10210.yaml", "Counter-Strike-10210")
        self.assertIn("cstrike/cl_dlls/client.dll", paths)
        self.assertIn("cstrike/cl_dlls/client.so", paths)
        self.assertIn("cstrike/dlls/cs.so", paths)
        self.assertNotIn("Counter-Strike-10210/cstrike/cl_dlls/client.dll", paths)
        self.assertEqual(len(paths), len(set(paths)))

    def test_filelist_rejects_paths_outside_basepath(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text(
                """modules:
  - name: engine
    path_windows: Other/hw.dll
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(download_depot.ConfigError, "basepath"):
                download_depot.load_module_filelist(path, "Game")

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
        self.assertIn("-all-platforms", command)
        self.assertNotIn("-os", command)
        self.assertIn("-remember-password", command)

    def test_download_uses_basepath_install_directory(self):
        entry = {
            "appid": 10,
            "basepath": "Half-Life",
            "manifests": {"11": "123"},
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(download_depot, "run_command") as run,
            patch.object(download_depot, "verify_downloaded_files", create=True) as verify,
        ):
            download_depot.download_manifests(
                entry=entry,
                os_name="windows",
                depot_dir=Path(temporary) / "depots",
                filelist=["cstrike/cl_dlls/client.dll"],
            )
        command = run.call_args.args[0]
        expected = Path(temporary) / "depots" / "Half-Life"
        self.assertEqual(str(expected), command[command.index("-dir") + 1])
        verify.assert_called_once_with(expected, ["cstrike/cl_dlls/client.dll"])

    def test_verify_downloaded_files_rejects_missing_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            install_dir = Path(temporary) / "Game"
            present = install_dir / "hw.dll"
            present.parent.mkdir(parents=True)
            present.write_bytes(b"binary")
            with self.assertRaisesRegex(download_depot.ConfigError, "missing"):
                download_depot.verify_downloaded_files(install_dir, ["hw.dll", "hw.so"])

    def test_tag_and_all_are_mutually_exclusive_and_required(self):
        with self.assertRaises(SystemExit):
            download_depot.parse_args([])
        with self.assertRaises(SystemExit):
            download_depot.parse_args(["-tag", "cstrike-10210", "-all"])
        args = download_depot.parse_args(["-all"])
        self.assertTrue(args.all)
        self.assertIsNone(args.tag)
        args = download_depot.parse_args(["-tag", "cstrike-10210"])
        self.assertFalse(args.all)
        self.assertEqual("cstrike-10210", args.tag)

    def test_download_all_tags_loops_over_config_and_reports_failures(self):
        config = Path(__file__).parents[1] / "download.yaml"
        entries = download_depot.load_downloads(config)
        with (
            patch.object(download_depot, "download_entry") as entry,
            patch.object(download_depot, "load_downloads", return_value=entries),
            patch.object(download_depot, "parse_args") as parse,
        ):
            parse.return_value = download_depot.parse_args(["-all"])
            result = download_depot.download_all_tags(parse.return_value)
        self.assertEqual(0, result)
        self.assertEqual(len(entries), entry.call_count)

    def test_download_all_tags_continues_past_failures(self):
        entries = [
            {"tag": "game-1", "appid": 1, "basepath": "Game", "manifests": {"1": "1"}},
            {"tag": "game-2", "appid": 1, "basepath": "Game", "manifests": {"1": "1"}},
            {"tag": "game-3", "appid": 1, "basepath": "Game", "manifests": {"1": "1"}},
        ]
        with (
            patch.object(download_depot, "download_entry") as entry,
            patch.object(download_depot, "load_downloads", return_value=entries),
            patch.object(download_depot, "parse_args") as parse,
        ):
            parse.return_value = download_depot.parse_args(["-all"])
            entry.side_effect = [None, download_depot.ConfigError("boom"), None]
            result = download_depot.download_all_tags(parse.return_value)
        self.assertEqual(1, result)
        self.assertEqual(3, entry.call_count)
        self.assertEqual("game-1", entry.call_args_list[0].args[1]["tag"])
        self.assertEqual("game-3", entry.call_args_list[2].args[1]["tag"])


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
                            {"name": "Engine", "path_windows": "Game/a.dll", "module_windows": "a.dll"},
                            {"name": "engine", "path_windows": "Game/b.dll", "module_windows": "b.dll"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises((TypeError, ValueError)):
                copy_depot_bin.parse_config(path)


if __name__ == "__main__":
    unittest.main()
