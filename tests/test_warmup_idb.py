from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import warmup_idb
from tests.test_decrypt_blob import make_blob
from tests.test_support import write_config, write_elf32, write_pe32

GAMEVER = "test-1"


def _fixture(root: Path, *, both_platforms=True, blob_windows=False):
    bindir = root / "bin"
    game_root = bindir / GAMEVER
    config = write_config(root / "config.yaml", both_platforms=both_platforms)
    payload = make_blob() if blob_windows else b""
    if blob_windows:
        (game_root / "engine" / "hw.dll").parent.mkdir(parents=True, exist_ok=True)
        (game_root / "engine" / "hw.dll").write_bytes(payload)
    else:
        write_pe32(game_root / "engine" / "hw.dll", payload)
    if both_platforms:
        write_elf32(game_root / "engine" / "hw.so")
    return bindir, config


def _run(bindir: Path, config: Path, extra=()):
    argv = ["-gamever", GAMEVER, "-config", str(config), "-bindir", str(bindir), "-python", sys.executable, *extra]
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = warmup_idb.main(argv)
    return exit_code, output.getvalue()


class DeclaredBinariesTests(unittest.TestCase):
    def test_declared_binaries_lists_windows_before_linux_per_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            _document, modules = warmup_idb.load_config(config)

            entries = warmup_idb.declared_binaries(bindir, GAMEVER, modules, "all-platform")

        self.assertEqual(
            [
                ("engine", "windows", bindir / GAMEVER / "engine" / "hw.dll"),
                ("engine", "linux", bindir / GAMEVER / "engine" / "hw.so"),
            ],
            entries,
        )

    def test_declared_binaries_honors_a_single_platform_filter(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            _document, modules = warmup_idb.load_config(config)

            entries = warmup_idb.declared_binaries(bindir, GAMEVER, modules, "linux")

        self.assertEqual([("engine", "linux", bindir / GAMEVER / "engine" / "hw.so")], entries)


class WarmDatabaseDetectionTests(unittest.TestCase):
    def test_primary_database_is_warm_without_a_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = write_pe32(Path(temporary) / "engine" / "hw.dll")
            self.assertFalse(warmup_idb.has_warm_database(binary))

            Path(f"{binary}.i64").write_bytes(b"database")

            self.assertTrue(warmup_idb.has_warm_database(binary))

    def test_active_lock_makes_an_existing_database_not_warm(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = write_pe32(Path(temporary) / "engine" / "hw.dll")
            Path(f"{binary}.i64").write_bytes(b"database")
            Path(f"{binary}.id0").write_bytes(b"lock")

            self.assertFalse(warmup_idb.has_warm_database(binary))


class WarmupProducerTests(unittest.TestCase):
    def _warm_groups(self, calls):
        return [(call.kwargs["identity"], call.kwargs["workspace_root"]) for call in calls]

    def test_every_binary_already_warm_skips_the_warm_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            for name in ("hw.dll", "hw.so"):
                Path(f"{bindir / GAMEVER / 'engine' / name}.i64").write_bytes(b"database")

            with patch.object(warmup_idb, "warm_group") as warm_group:
                exit_code, output = _run(bindir, config)

        self.assertEqual(0, exit_code)
        self.assertEqual(0, warm_group.call_count)
        self.assertIn("already warm; nothing to do", output)

    def test_only_pending_binaries_are_warmed_in_one_group_per_platform(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            Path(f"{bindir / GAMEVER / 'engine' / 'hw.dll'}.i64").write_bytes(b"database")

            with (
                patch.object(warmup_idb, "probe_ida_kernel_version", return_value="9.3"),
                patch.object(warmup_idb, "warm_group") as warm_group,
            ):
                exit_code, _output = _run(bindir, config)

        self.assertEqual(0, exit_code)
        self.assertEqual(1, warm_group.call_count)
        identity, workspace_root = self._warm_groups(warm_group.call_args_list)[0]
        self.assertEqual(bindir / GAMEVER, workspace_root)
        self.assertEqual(GAMEVER, identity["tag"])
        self.assertEqual({"kernel_version": "9.3"}, identity["ida_runtime"])
        self.assertEqual(
            [{"module": "engine", "platform": "linux", "path": "engine/hw.so"}],
            [{key: record[key] for key in ("module", "platform", "path")} for record in identity["binaries"]],
        )

    def test_force_rewarms_the_windows_group_that_is_already_warm(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            for name in ("hw.dll", "hw.so"):
                Path(f"{bindir / GAMEVER / 'engine' / name}.i64").write_bytes(b"database")

            with (
                patch.object(warmup_idb, "probe_ida_kernel_version", return_value="9.3"),
                patch.object(warmup_idb, "warm_group") as warm_group,
            ):
                exit_code, _output = _run(bindir, config, ("-force",))

        self.assertEqual(0, exit_code)
        self.assertEqual(
            ["windows", "linux"],
            [identity["binaries"][0]["platform"] for identity, _ in self._warm_groups(warm_group.call_args_list)],
        )

    def test_blob_source_is_rewritten_and_the_decrypted_sibling_is_warmed(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary), both_platforms=False, blob_windows=True)

            with (
                patch.object(warmup_idb, "probe_ida_kernel_version", return_value="9.3"),
                patch.object(warmup_idb, "warm_group") as warm_group,
            ):
                exit_code, _output = _run(bindir, config)

            self.assertTrue((bindir / GAMEVER / "engine" / "hw.decrypt.dll").is_file())
        self.assertEqual(0, exit_code)
        identity, _workspace_root = self._warm_groups(warm_group.call_args_list)[0]
        self.assertEqual("engine/hw.decrypt.dll", identity["binaries"][0]["path"])

    def test_a_platform_worker_failure_is_reported_and_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))

            def failing_group(**_kwargs):
                raise warmup_idb.IdbCacheError("worker exploded")

            with (
                patch.object(warmup_idb, "probe_ida_kernel_version", return_value="9.3"),
                patch.object(warmup_idb, "warm_group", side_effect=failing_group),
            ):
                exit_code, output = _run(bindir, config)

        self.assertEqual(1, exit_code)
        self.assertIn("Warmup failed: 2 of 2 databases were not warmed", output)

    def test_a_missing_configured_binary_is_reported_before_any_warming(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            (bindir / GAMEVER / "engine" / "hw.so").unlink()

            with patch.object(warmup_idb, "warm_group") as warm_group:
                exit_code, output = _run(bindir, config)

        self.assertEqual(1, exit_code)
        self.assertEqual(0, warm_group.call_count)
        self.assertIn("Error: engine/linux:", output)


class WarmupArgumentTests(unittest.TestCase):
    def test_a_tag_without_a_matching_config_fails(self):
        exit_code, output = _run(Path("missing-bin"), Path("missing-config.yaml"))

        self.assertEqual(1, exit_code)
        self.assertIn("Analysis config file not found", output)

    def test_an_unresolvable_interpreter_fails_before_warming(self):
        with tempfile.TemporaryDirectory() as temporary:
            bindir, config = _fixture(Path(temporary))
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = warmup_idb.main(
                    [
                        "-gamever",
                        GAMEVER,
                        "-config",
                        str(config),
                        "-bindir",
                        str(bindir),
                        "-python",
                        "no-such-ida-python",
                    ]
                )

        self.assertEqual(1, exit_code)
        self.assertIn("interpreter with idalib not found", output.getvalue())

    def test_parse_args_rejects_an_unknown_platform(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            warmup_idb.parse_args(["-gamever", GAMEVER, "-python", sys.executable, "-platform", "dos"])

    def test_selected_platforms_expands_all_platform(self):
        self.assertEqual(("windows", "linux"), warmup_idb.selected_platforms("all-platform"))
        self.assertEqual(("linux",), warmup_idb.selected_platforms("linux"))
