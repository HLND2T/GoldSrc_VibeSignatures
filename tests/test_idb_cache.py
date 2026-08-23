from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ida_database_paths import (
    IdaDatabasePathError,
    database_file_role,
    database_lock_paths,
    database_paths,
    primary_database_paths,
    validate_database_file_set,
)
from idb_cache import (
    IdbCacheError,
    build_binary_identity,
    build_cache_identity,
    cache_key,
    probe_generation,
    prune_tag,
    publish_generation,
    restore_generation,
    verify_selection,
    warm_and_publish,
)
from idb_warm_worker import probe_runtime_contract
from release_workflow_lib.hashing import canonical_json_bytes, write_canonical_json
from tests.test_support import write_elf32, write_pe32


def cache_fixture(root: Path):
    workspace = root / "workspace"
    persisted = root / "persisted"
    persisted.mkdir()
    binary = write_pe32(workspace / "engine" / "hw.dll", b"cache-input")
    Path(f"{binary}.i64").write_bytes(b"primary-idb")
    Path(f"{binary}.i64.nam").write_bytes(b"names")
    worker = root / "worker.py"
    worker.write_text("worker contract\n", encoding="utf-8")
    runtime = {
        "kernel_version": "9.3",
        "processor": "metapc",
        "bitness": 32,
        "file_type": "PE",
        "loader_name": "pe",
        "loader_module_sha256": "1" * 64,
        "plugins": [],
    }
    binary_identity = build_binary_identity(
        workspace_root=workspace,
        module="engine",
        platform="windows",
        relative_path="engine/hw.dll",
    )
    identity = build_cache_identity(
        tag="game-1",
        ida_runtime=runtime,
        normalized_ida_args=["-A"],
        binaries=[binary_identity],
        warm_worker_path=worker,
    )
    return workspace, persisted, binary, identity


class IdaDatabasePathTests(unittest.TestCase):
    def test_enumerates_primary_side_and_lock_files_for_both_database_suffixes(self):
        binary = Path("engine/hw.dll")
        self.assertEqual(
            (Path("engine/hw.dll.i64"), Path("engine/hw.dll.idb")),
            primary_database_paths(binary),
        )
        paths = database_paths(binary)
        self.assertIn(Path("engine/hw.dll.i64.nam"), paths)
        self.assertIn(Path("engine/hw.dll.idb.til"), paths)
        self.assertIn(Path("engine/hw.dll.id1"), paths)
        self.assertEqual(
            (Path("engine/hw.dll.id0"), Path("engine/hw.dll.i64.id0"), Path("engine/hw.dll.idb.id0")),
            database_lock_paths(binary),
        )
        self.assertEqual("primary", database_file_role(binary, Path("engine/hw.dll.idb")))
        self.assertEqual("side", database_file_role(binary, Path("engine/hw.dll.i64.nam")))

    def test_requires_exactly_one_primary_and_rejects_active_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            with self.assertRaises(IdaDatabasePathError):
                validate_database_file_set(binary)
            Path(f"{binary}.i64").write_bytes(b"i64")
            Path(f"{binary}.idb").write_bytes(b"idb")
            with self.assertRaises(IdaDatabasePathError):
                validate_database_file_set(binary)
            Path(f"{binary}.idb").unlink()
            Path(f"{binary}.id0").write_bytes(b"lock")
            with self.assertRaisesRegex(IdaDatabasePathError, "lock"):
                validate_database_file_set(binary)


class IdbCacheIdentityTests(unittest.TestCase):
    def test_runtime_probe_binds_binary_loader_and_allowlisted_plugins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ida_root = root / "ida"
            loaders = ida_root / "loaders"
            plugins = ida_root / "plugins"
            loaders.mkdir(parents=True)
            plugins.mkdir()
            (loaders / "pe.dll").write_bytes(b"pe-loader")
            (loaders / "elf.dll").write_bytes(b"elf-loader")
            (plugins / "allowed.dll").write_bytes(b"plugin")
            pe = write_pe32(root / "hw.dll")
            elf = write_elf32(root / "hw.so")
            pe_runtime = probe_runtime_contract(
                ida_root=ida_root,
                kernel_version="9.3",
                binary_path=pe,
                plugins=("allowed.dll",),
            )
            elf_runtime = probe_runtime_contract(
                ida_root=ida_root,
                kernel_version="9.3",
                binary_path=elf,
            )
            self.assertEqual(
                ("PE", "pe", 32), (pe_runtime["file_type"], pe_runtime["loader_name"], pe_runtime["bitness"])
            )
            self.assertEqual(
                ("ELF", "elf", 32), (elf_runtime["file_type"], elf_runtime["loader_name"], elf_runtime["bitness"])
            )
            self.assertNotEqual(pe_runtime["loader_module_sha256"], elf_runtime["loader_module_sha256"])
            self.assertEqual("allowed.dll", pe_runtime["plugins"][0]["name"])

    def test_key_is_sensitive_to_binary_runtime_args_worker_and_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, _persisted, _binary, identity = cache_fixture(root)
            original = cache_key(identity)
            mutations = []
            runtime = {**identity["ida_runtime"], "kernel_version": "9.4"}
            mutations.append({**identity, "ida_runtime": runtime})
            mutations.append({**identity, "normalized_ida_args": ["-B"]})
            mutations.append({**identity, "warm_worker_sha256": "2" * 64})
            moved = {**identity["binaries"][0], "path": "engine/renamed.dll"}
            mutations.append({**identity, "binaries": [moved]})
            changed = {**identity["binaries"][0], "sha256": "3" * 64}
            mutations.append({**identity, "binaries": [changed]})
            self.assertEqual(5, len({cache_key(mutation) for mutation in mutations}))
            self.assertTrue(all(cache_key(mutation) != original for mutation in mutations))
            self.assertTrue(workspace.is_dir())

    def test_identity_rejects_path_escape_case_collision_and_mixed_loader_platform(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _workspace, _persisted, _binary, identity = cache_fixture(root)
            escaped = {**identity["binaries"][0], "path": "../hw.dll"}
            with self.assertRaises(IdbCacheError):
                cache_key({**identity, "binaries": [escaped]})
            collision = {**identity["binaries"][0], "path": "engine/HW.dll", "module": "engine2"}
            collision["path"] = "engine2/HW.dll"
            duplicate = {**identity["binaries"][0], "module": "engine2", "path": "engine2/hw.dll"}
            with self.assertRaises(IdbCacheError):
                cache_key({**identity, "binaries": [collision, duplicate]})
            linux = {**identity["binaries"][0], "platform": "linux"}
            with self.assertRaises(IdbCacheError):
                cache_key({**identity, "binaries": [linux]})


class IdbCacheGenerationTests(unittest.TestCase):
    def test_publish_probe_verify_restore_and_exact_selection_are_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, persisted, binary, identity = cache_fixture(root)
            first = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-1",
                attempt=1,
                published_at="2026-01-01T00:00:00Z",
            )
            self.assertEqual(first, probe_generation(persisted_root=persisted, identity=identity))
            manifest = verify_selection(persisted_root=persisted, selection=first)
            self.assertEqual(cache_key(identity), manifest["cache_key"])
            first_again = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-1",
                attempt=1,
                published_at="2026-01-01T00:00:00Z",
            )
            self.assertEqual(first, first_again)
            second = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-2",
                attempt=1,
                published_at="2026-01-02T00:00:00Z",
            )
            self.assertNotEqual(first["generation"], second["generation"])
            Path(f"{binary}.i64").write_bytes(b"modified selected-node database")
            restore_generation(persisted_root=persisted, selection=first, workspace_root=workspace)
            self.assertEqual(b"primary-idb", Path(f"{binary}.i64").read_bytes())
            self.assertEqual(second, probe_generation(persisted_root=persisted, identity=identity))

    def test_tampered_payload_manifest_binary_and_lock_are_rejected(self):
        mutations = ("database", "manifest", "binary", "lock")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace, persisted, binary, identity = cache_fixture(root)
                selection = publish_generation(
                    persisted_root=persisted,
                    identity=identity,
                    workspace_root=workspace,
                    run_id="run-1",
                    attempt=1,
                )
                generation = persisted / "idb-cache" / "game-1" / "generations" / selection["generation"]
                if mutation == "database":
                    path = generation / "payload" / "databases" / "engine" / "hw.dll.i64"
                    path.write_bytes(b"tampered")
                    with self.assertRaises(IdbCacheError):
                        verify_selection(persisted_root=persisted, selection=selection)
                elif mutation == "manifest":
                    path = generation / "manifest.json"
                    document = json.loads(path.read_bytes())
                    document["payload_inventory_sha256"] = "0" * 64
                    path.write_bytes(canonical_json_bytes(document))
                    with self.assertRaises(IdbCacheError):
                        verify_selection(persisted_root=persisted, selection=selection)
                elif mutation == "binary":
                    binary.write_bytes(b"tampered workspace binary")
                    with self.assertRaises(IdbCacheError):
                        restore_generation(persisted_root=persisted, selection=selection, workspace_root=workspace)
                else:
                    Path(f"{binary}.id0").write_bytes(b"lock")
                    with self.assertRaises(IdbCacheError):
                        restore_generation(persisted_root=persisted, selection=selection, workspace_root=workspace)

    def test_reparse_payload_is_rejected_when_symlinks_are_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, persisted, _binary, identity = cache_fixture(root)
            selection = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-1",
                attempt=1,
            )
            generation = persisted / "idb-cache" / "game-1" / "generations" / selection["generation"]
            database = generation / "payload" / "databases" / "engine" / "hw.dll.i64"
            target = root / "outside.idb"
            target.write_bytes(database.read_bytes())
            database.unlink()
            try:
                os.symlink(target, database)
            except OSError as exc:
                self.skipTest(f"Symlink creation is unavailable: {exc}")
            with self.assertRaises(IdbCacheError):
                verify_selection(persisted_root=persisted, selection=selection)

    def test_prune_keeps_ready_latest_three_and_removes_old_incoming(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, persisted, _binary, identity = cache_fixture(root)
            selections = []
            for index in range(5):
                selections.append(
                    publish_generation(
                        persisted_root=persisted,
                        identity=identity,
                        workspace_root=workspace,
                        run_id=f"run-{index}",
                        attempt=1,
                        published_at=f"2026-01-0{index + 1}T00:00:00Z",
                    )
                )
            generations = persisted / "idb-cache" / "game-1" / "generations"
            incoming = generations / ".incoming-stale"
            incoming.mkdir()
            os.utime(incoming, (0, 0))
            removed = prune_tag(
                persisted_root=persisted,
                tag="game-1",
                now=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )
            self.assertIn(".incoming-stale", removed)
            self.assertFalse((generations / selections[0]["generation"]).exists())
            self.assertFalse((generations / selections[1]["generation"]).exists())
            self.assertTrue(all((generations / item["generation"]).is_dir() for item in selections[2:]))

    def test_warm_timeout_cleans_incomplete_database_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, persisted, binary, identity = cache_fixture(root)
            identity_path = root / "identity.json"
            write_canonical_json(identity_path, identity)
            with (
                patch("idb_cache.subprocess.run", side_effect=subprocess.TimeoutExpired(["worker"], 1)),
                self.assertRaisesRegex(IdbCacheError, "timed out"),
            ):
                warm_and_publish(
                    persisted_root=persisted,
                    identity_path=identity_path,
                    workspace_root=workspace,
                    run_id="run-1",
                    attempt=1,
                    port_lock=root / "port.lock",
                    timeout_seconds=1,
                )
            self.assertFalse(Path(f"{binary}.i64").exists())
            self.assertFalse((persisted / "idb-cache").exists())

    def test_warm_observed_runtime_mismatch_cleans_database_and_does_not_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, persisted, binary, identity = cache_fixture(root)
            identity_path = root / "identity.json"
            write_canonical_json(identity_path, identity)

            def fake_worker(command, **_kwargs):
                output = Path(command[command.index("-output") + 1])
                workspace_root = Path(command[command.index("-workspace-root") + 1])
                Path(f"{workspace_root / 'engine' / 'hw.dll'}.i64").write_bytes(b"new warm database")
                write_canonical_json(output, {**identity["ida_runtime"], "kernel_version": "9.4"})
                return SimpleNamespace(returncode=0)

            with (
                patch("idb_cache.subprocess.run", side_effect=fake_worker),
                self.assertRaisesRegex(IdbCacheError, "observed runtime identity"),
            ):
                warm_and_publish(
                    persisted_root=persisted,
                    identity_path=identity_path,
                    workspace_root=workspace,
                    run_id="run-1",
                    attempt=1,
                    port_lock=root / "port.lock",
                    timeout_seconds=1,
                )
            self.assertFalse(Path(f"{binary}.i64").exists())
            self.assertFalse((persisted / "idb-cache").exists())


if __name__ == "__main__":
    unittest.main()
