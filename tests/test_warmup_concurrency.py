from __future__ import annotations

import ctypes
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import idb_cache
from ida_database_paths import database_cleanup_paths, database_lock_paths, database_paths
from idb_cache import IdbCacheError, build_binary_identity, build_cache_identity, warm_group
from idb_warm_worker import warm_binary
from tests.test_support import write_pe32
from warmup_memory import (
    DEFAULT_INITIAL_WORKER_RESERVATION_BYTES,
    MemorySnapshot,
    ProducerMemoryOwner,
    WindowsJobMemoryController,
)


class DatabaseCleanupPathTests(unittest.TestCase):
    def test_cleanup_paths_stably_include_database_and_lock_files(self):
        binary = Path("engine/hw.dll")
        self.assertEqual(
            tuple(dict.fromkeys((*database_paths(binary), *database_lock_paths(binary)))),
            database_cleanup_paths(binary),
        )


class WarmWorkerLifecycleTests(unittest.TestCase):
    def _modules(self, *, auto_result=True, auto_error=None, close_error=None):
        idapro = SimpleNamespace(
            open_database=Mock(return_value=0),
            close_database=Mock(side_effect=close_error),
        )
        ida_auto = SimpleNamespace(auto_wait=Mock(return_value=auto_result, side_effect=auto_error))
        ida_loader = SimpleNamespace(save_database=Mock(return_value=True))
        return idapro, ida_auto, ida_loader

    def test_auto_wait_false_closes_without_saving(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = write_pe32(Path(temporary) / "hw.dll")
            modules = self._modules(auto_result=False)
            with (
                patch("idb_warm_worker._load_ida_modules", return_value=modules),
                patch("idb_warm_worker._apply_memory_limit"),
                self.assertRaisesRegex(ValueError, "auto-analysis did not complete"),
            ):
                warm_binary(binary, memory_limit_mb=8192)
            modules[1].auto_wait.assert_called_once_with()
            modules[2].save_database.assert_not_called()
            modules[0].close_database.assert_called_once_with()

    def test_auto_wait_error_remains_primary_when_close_also_fails(self):
        analysis_error = RuntimeError("analysis failed")
        close_error = RuntimeError("close failed")
        with tempfile.TemporaryDirectory() as temporary:
            binary = write_pe32(Path(temporary) / "hw.dll")
            modules = self._modules(auto_error=analysis_error, close_error=close_error)
            with (
                patch("idb_warm_worker._load_ida_modules", return_value=modules),
                patch("idb_warm_worker._apply_memory_limit"),
                self.assertRaisesRegex(RuntimeError, "analysis failed") as raised,
            ):
                warm_binary(binary, memory_limit_mb=8192)
            self.assertIs(close_error, raised.exception.__cause__)
            modules[2].save_database.assert_not_called()

    def test_success_orders_open_analysis_save_and_close(self):
        calls = []
        modules = self._modules()
        modules[0].open_database.side_effect = lambda *_args, **_kwargs: calls.append("open") or 0
        modules[1].auto_wait.side_effect = lambda: calls.append("auto") or True
        modules[2].save_database.side_effect = lambda *_args: calls.append("save") or True
        modules[0].close_database.side_effect = lambda: calls.append("close")
        with tempfile.TemporaryDirectory() as temporary:
            binary = write_pe32(Path(temporary) / "hw.dll")
            with (
                patch("idb_warm_worker._load_ida_modules", return_value=modules),
                patch("idb_warm_worker._apply_memory_limit"),
            ):
                warm_binary(binary, memory_limit_mb=8192)
        self.assertEqual(["open", "auto", "save", "close"], calls)

    def test_orchestrator_modules_import_without_loading_ida_apis(self):
        script = """
import importlib.abc
import sys

class BlockIda(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"idapro", "idaapi", "ida_auto", "ida_loader"}:
            raise AssertionError(f"unexpected IDA import: {fullname}")
        return None

sys.meta_path.insert(0, BlockIda())
import idb_warm_worker
import idb_cache_release
import idb_cache_workflow
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


class ProducerMemoryOwnerTests(unittest.TestCase):
    def test_controller_closes_only_an_unbound_handle_when_initialization_fails(self):
        api = SimpleNamespace(
            create_job=Mock(return_value=123),
            set_job_memory_limit=Mock(side_effect=OSError("limit failed")),
            assign_current_process=Mock(),
            query_job_memory=Mock(),
            close_handle=Mock(),
        )
        with self.assertRaisesRegex(OSError, "limit failed"):
            WindowsJobMemoryController(10_000, api=api)
        api.assign_current_process.assert_not_called()
        api.close_handle.assert_called_once_with(123)

    def test_controller_is_reused_but_each_group_gets_a_fresh_gate(self):
        controller = SimpleNamespace(snapshot=Mock(return_value=MemorySnapshot(job_bytes=1)), budget_bytes=10_000)
        factory = Mock(return_value=controller)
        owner = ProducerMemoryOwner(10_000, controller_factory=factory, initial_worker_reservation_bytes=10)

        first = owner.begin_group()
        owner.end_group(first)
        second = owner.begin_group()
        owner.end_group(second)

        factory.assert_called_once_with(10_000)
        self.assertIsNot(first, second)
        self.assertEqual(2, controller.snapshot.call_count)

    def test_unsatisfiable_budget_fails_before_gate_creation_and_keeps_controller(self):
        budget = DEFAULT_INITIAL_WORKER_RESERVATION_BYTES
        controller = SimpleNamespace(snapshot=Mock(return_value=MemorySnapshot(job_bytes=0)), budget_bytes=budget)
        factory = Mock(return_value=controller)
        owner = ProducerMemoryOwner(budget, controller_factory=factory)

        with self.assertRaisesRegex(ValueError, "cannot satisfy"):
            owner.begin_group()

        self.assertIs(controller, owner.controller)

    def test_soft_limit_boundary_equal_is_allowed_and_one_byte_over_is_rejected(self):
        allowed_controller = SimpleNamespace(
            snapshot=Mock(return_value=MemorySnapshot(job_bytes=0)),
            budget_bytes=100,
        )
        allowed = ProducerMemoryOwner(
            100,
            controller_factory=Mock(return_value=allowed_controller),
            soft_limit_ratio=0.85,
            initial_worker_reservation_bytes=85,
        )
        gate = allowed.begin_group()
        allowed.end_group(gate)

        rejected_controller = SimpleNamespace(
            snapshot=Mock(return_value=MemorySnapshot(job_bytes=0)),
            budget_bytes=100,
        )
        rejected = ProducerMemoryOwner(
            100,
            controller_factory=Mock(return_value=rejected_controller),
            soft_limit_ratio=0.85,
            initial_worker_reservation_bytes=86,
        )
        with self.assertRaisesRegex(ValueError, "cannot satisfy"):
            rejected.begin_group()


def warm_group_fixture(root: Path):
    workspace = root / "workspace"
    binaries = []
    paths = []
    for module, filename in (("client", "client.dll"), ("engine", "hw.dll")):
        binary = write_pe32(workspace / module / filename, module.encode("ascii"))
        paths.append(binary)
        binaries.append(
            build_binary_identity(
                workspace_root=workspace,
                module=module,
                platform="windows",
                relative_path=f"{module}/{filename}",
            )
        )
    identity = build_cache_identity(
        tag="game-1",
        ida_runtime={"kernel_version": "9.3"},
        binaries=binaries,
        warm_worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
    )
    return workspace, paths, identity


class WarmGroupSchedulingTests(unittest.TestCase):
    def test_version_probe_uses_the_bound_executable_without_an_internal_timeout(self):
        completed = SimpleNamespace(returncode=0, stdout="9.3\n", stderr="")
        with patch("idb_cache.subprocess.run", return_value=completed) as run:
            self.assertEqual("9.3", idb_cache.probe_ida_kernel_version(sys.executable))
        command = run.call_args.args[0]
        self.assertEqual(str(Path(sys.executable).resolve()), command[0])
        self.assertEqual(
            str(Path(idb_cache.__file__).with_name("idb_warm_worker.py").resolve()),
            command[1],
        )
        self.assertEqual("--print-ida-version", command[2])
        self.assertNotIn("timeout", run.call_args.kwargs)

    def test_max_concurrency_bounds_workers_and_explicit_ida_python_is_used(self):
        def observed_maximum(root: Path, max_concurrency: int):
            workspace, _paths, identity = warm_group_fixture(root)
            active = 0
            maximum = 0
            seen_executables = []
            state_lock = threading.Lock()

            def fake_worker(**kwargs):
                nonlocal active, maximum
                with state_lock:
                    active += 1
                    maximum = max(maximum, active)
                    seen_executables.append(kwargs["ida_python_executable"])
                time.sleep(0.03)
                with state_lock:
                    active -= 1
                return 0.03

            with (
                patch("idb_cache.probe_ida_kernel_version", return_value="9.3"),
                patch("idb_cache._run_one_worker", side_effect=fake_worker),
            ):
                warm_group(
                    identity=identity,
                    workspace_root=workspace,
                    ida_python_executable=sys.executable,
                    max_concurrency=max_concurrency,
                    worker_timeout_seconds=1,
                    producer_memory=ProducerMemoryOwner(None),
                )
            return maximum, seen_executables

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            serial_maximum, _serial_executables = observed_maximum(root / "serial", 1)
            parallel_maximum, parallel_executables = observed_maximum(root / "parallel", 2)
        self.assertEqual(1, serial_maximum)
        self.assertEqual(2, parallel_maximum)
        self.assertEqual(
            [Path(sys.executable).resolve()] * 2,
            parallel_executables,
        )

    def test_one_worker_failure_cleans_only_itself_and_keeps_successful_sibling(self):
        class FakeProcess:
            def __init__(self, return_code):
                self.return_code = return_code

            def wait(self, timeout=None):
                return self.return_code

            def kill(self):
                raise AssertionError("successful wait must not kill the worker")

        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, identity = warm_group_fixture(Path(temporary))

            def fake_popen(command):
                binary = Path(command[command.index("-binary") + 1])
                Path(f"{binary}.i64").write_bytes(b"partial-or-complete")
                return FakeProcess(1 if binary.name == "client.dll" else 0)

            with (
                patch("idb_cache.probe_ida_kernel_version", return_value="9.3"),
                patch("idb_cache.subprocess.Popen", side_effect=fake_popen),
                self.assertRaisesRegex(IdbCacheError, "1 worker"),
            ):
                warm_group(
                    identity=identity,
                    workspace_root=workspace,
                    ida_python_executable=sys.executable,
                    max_concurrency=2,
                    worker_timeout_seconds=1,
                    producer_memory=ProducerMemoryOwner(None),
                )
            client, engine = binaries
            self.assertFalse(Path(f"{client}.i64").exists())
            self.assertTrue(Path(f"{engine}.i64").is_file())

    def test_version_mismatch_fails_before_cleanup_or_worker_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, identity = warm_group_fixture(Path(temporary))
            existing = Path(f"{binaries[0]}.i64")
            existing.write_bytes(b"existing")
            with (
                patch("idb_cache.probe_ida_kernel_version", return_value="9.4"),
                patch("idb_cache.subprocess.Popen") as popen,
                self.assertRaisesRegex(IdbCacheError, "version mismatch"),
            ):
                warm_group(
                    identity=identity,
                    workspace_root=workspace,
                    ida_python_executable=sys.executable,
                    max_concurrency=2,
                    worker_timeout_seconds=1,
                    producer_memory=ProducerMemoryOwner(None),
                )
            popen.assert_not_called()
            self.assertEqual(b"existing", existing.read_bytes())

    def test_memory_budget_initialization_failure_precedes_cleanup_and_futures(self):
        owner = SimpleNamespace(
            budget_bytes=4096 * 1024 * 1024,
            begin_group=Mock(side_effect=ValueError("budget cannot satisfy")),
            end_group=Mock(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, identity = warm_group_fixture(Path(temporary))
            existing = Path(f"{binaries[0]}.i64")
            existing.write_bytes(b"existing")
            with (
                patch("idb_cache.probe_ida_kernel_version", return_value="9.3"),
                patch("idb_cache._run_one_worker") as worker,
                self.assertRaisesRegex(ValueError, "cannot satisfy"),
            ):
                warm_group(
                    identity=identity,
                    workspace_root=workspace,
                    ida_python_executable=sys.executable,
                    max_concurrency=2,
                    worker_timeout_seconds=1,
                    producer_memory=owner,
                )
            worker.assert_not_called()
            owner.end_group.assert_not_called()
            self.assertEqual(b"existing", existing.read_bytes())


class WarmFailureCleanupTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows path aliases are required")
    def test_worker_normalizes_windows_short_and_long_path_aliases_before_relative_to(self):
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_short_path_name = kernel32.GetShortPathNameW
        get_short_path_name.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        get_short_path_name.restype = ctypes.c_uint32

        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, _identity = warm_group_fixture(Path(temporary))
            workspace = workspace.resolve(strict=True)
            binary = binaries[0].resolve(strict=True)
            required = get_short_path_name(str(binary), None, 0)
            if required == 0:
                self.skipTest(f"GetShortPathNameW failed with error {ctypes.get_last_error()}")
            buffer = ctypes.create_unicode_buffer(required)
            written = get_short_path_name(str(binary), buffer, required)
            if written == 0:
                self.skipTest(f"GetShortPathNameW failed with error {ctypes.get_last_error()}")
            short_binary = Path(buffer.value)
            if short_binary == binary:
                self.skipTest("8.3 short path names are unavailable on this volume")
            self.assertTrue(short_binary.samefile(binary))

            gate = SimpleNamespace(
                wait_for_launch=Mock(side_effect=TimeoutError("pressure")),
                worker_finished=Mock(),
            )
            with (
                patch("idb_cache._prepare_database_files_for_warm") as prepare,
                patch("idb_cache.subprocess.Popen") as popen,
                self.assertRaisesRegex(IdbCacheError, "admission timed out"),
            ):
                idb_cache._run_one_worker(
                    workspace=workspace,
                    binary=short_binary,
                    ida_python_executable=Path(sys.executable).resolve(),
                    worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
                    worker_timeout_seconds=1,
                    memory_gate=gate,
                    memory_admission_timeout_seconds=1,
                )
            prepare.assert_not_called()
            popen.assert_not_called()
            gate.worker_finished.assert_not_called()

    def test_startup_lock_is_preserved_and_prevents_worker_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, _identity = warm_group_fixture(Path(temporary))
            binary = binaries[0]
            lock = Path(f"{binary}.id0")
            lock.write_bytes(b"possibly-active")
            with (
                patch("idb_cache.subprocess.Popen") as popen,
                self.assertRaisesRegex(IdbCacheError, "Active IDA database lock"),
            ):
                idb_cache._run_one_worker(
                    workspace=workspace.resolve(),
                    binary=binary,
                    ida_python_executable=Path(sys.executable).resolve(),
                    worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
                    worker_timeout_seconds=1,
                    memory_gate=None,
                    memory_admission_timeout_seconds=1,
                )
            popen.assert_not_called()
            self.assertEqual(b"possibly-active", lock.read_bytes())

    def test_spawn_failure_releases_reservation_without_failed_worker_invalidation(self):
        gate = SimpleNamespace(wait_for_launch=Mock(), worker_finished=Mock())
        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, _identity = warm_group_fixture(Path(temporary))
            with (
                patch("idb_cache.subprocess.Popen", side_effect=OSError("spawn failed")),
                patch("idb_cache._invalidate_failed_worker_database") as invalidate,
                self.assertRaisesRegex(IdbCacheError, "could not start"),
            ):
                idb_cache._run_one_worker(
                    workspace=workspace.resolve(),
                    binary=binaries[0],
                    ida_python_executable=Path(sys.executable).resolve(),
                    worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
                    worker_timeout_seconds=1,
                    memory_gate=gate,
                    memory_admission_timeout_seconds=1,
                )
            gate.worker_finished.assert_called_once_with()
            invalidate.assert_not_called()

    def test_timeout_kills_and_waits_before_cleaning_complete_file_set(self):
        events = []

        class TimedOutProcess:
            def __init__(self):
                self.wait_count = 0

            def wait(self, timeout=None):
                self.wait_count += 1
                events.append("wait-timeout" if self.wait_count == 1 else "wait-reaped")
                if self.wait_count == 1:
                    raise subprocess.TimeoutExpired(["worker"], timeout)
                return -1

            def kill(self):
                events.append("kill")

        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, _identity = warm_group_fixture(Path(temporary))
            binary = binaries[0]

            def fake_popen(_command):
                events.append("popen")
                Path(f"{binary}.i64").write_bytes(b"partial")
                Path(f"{binary}.id0").write_bytes(b"stale-lock")
                return TimedOutProcess()

            original_cleanup = idb_cache._invalidate_failed_worker_database

            def cleanup_spy(*args):
                events.append("cleanup")
                return original_cleanup(*args)

            with (
                patch("idb_cache.subprocess.Popen", side_effect=fake_popen),
                patch("idb_cache._invalidate_failed_worker_database", side_effect=cleanup_spy),
                self.assertRaisesRegex(IdbCacheError, "timed out"),
            ):
                idb_cache._run_one_worker(
                    workspace=workspace.resolve(),
                    binary=binary,
                    ida_python_executable=Path(sys.executable).resolve(),
                    worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
                    worker_timeout_seconds=1,
                    memory_gate=None,
                    memory_admission_timeout_seconds=1,
                )
            self.assertEqual(["popen", "wait-timeout", "kill", "wait-reaped", "cleanup"], events)
            self.assertFalse(Path(f"{binary}.i64").exists())
            self.assertFalse(Path(f"{binary}.id0").exists())

    def test_admission_timeout_has_no_worker_or_cleanup_authority(self):
        gate = SimpleNamespace(
            wait_for_launch=Mock(side_effect=TimeoutError("pressure")),
            worker_finished=Mock(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, _identity = warm_group_fixture(Path(temporary))
            binary = binaries[0]
            database = Path(f"{binary}.i64")
            database.write_bytes(b"existing")
            with (
                patch("idb_cache._prepare_database_files_for_warm") as prepare,
                patch("idb_cache.subprocess.Popen") as popen,
                self.assertRaisesRegex(IdbCacheError, "admission timed out"),
            ):
                idb_cache._run_one_worker(
                    workspace=workspace.resolve(),
                    binary=binary,
                    ida_python_executable=Path(sys.executable).resolve(),
                    worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
                    worker_timeout_seconds=1,
                    memory_gate=gate,
                    memory_admission_timeout_seconds=1,
                )
            prepare.assert_not_called()
            popen.assert_not_called()
            gate.worker_finished.assert_not_called()
            self.assertEqual(b"existing", database.read_bytes())

    def test_invalidation_retries_only_windows_sharing_violations(self):
        class WindowsSharingViolation(OSError):
            winerror = 32

        with tempfile.TemporaryDirectory() as temporary:
            workspace, binaries, _identity = warm_group_fixture(Path(temporary))
            target = Path(f"{binaries[0]}.i64")
            target.write_bytes(b"partial")
            calls = 0
            original_unlink = Path.unlink

            def flaky_unlink(path, *args, **kwargs):
                nonlocal calls
                if path == target and calls < 2:
                    calls += 1
                    raise WindowsSharingViolation("sharing violation")
                return original_unlink(path, *args, **kwargs)

            with (
                patch.object(Path, "unlink", new=flaky_unlink),
                patch("idb_cache.time.sleep") as sleep,
            ):
                _removed, failures = idb_cache._invalidate_failed_worker_database(workspace.resolve(), binaries[0])
            self.assertEqual([], failures)
            self.assertFalse(target.exists())
            self.assertEqual(2, sleep.call_count)


if __name__ == "__main__":
    unittest.main()
