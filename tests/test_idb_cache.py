from __future__ import annotations

import json
import hashlib
import os
import ctypes
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ida_database_paths import (
    IdaDatabasePathError,
    database_cleanup_paths,
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
)
import idb_cache
import idb_cache_selection
from idb_cache_locks import IdbCacheError as IdbCacheLockError
from idb_cache_locks import exclusive_file_lock, lock_root, producer_lock_path, tag_lock
from idb_cache_release import (
    RELEASE_SELECTION_KEYS,
    RELEASE_SELECTION_SCHEMA_VERSION,
    IdbCacheReleaseError,
    prepare_release_selection,
    restore_release_selection,
    verify_release_selection_file,
)
from idb_cache_selection import (
    IdbCacheSelectionError,
    generation_selection,
    restore_selection_entries,
    validate_persisted_workspace,
)
from idb_cache_workflow import (
    CACHE_SELECTION_SCHEMA_VERSION,
    IdbCacheWorkflowError,
    SelectedBinaryGroup,
    prepare_cache_selection,
    restore_cache_selection,
    selected_binary_groups,
    validate_cache_selection,
    verify_cache_selection_file,
)
from gamesymbol_snapshot_lib.pr_validation import BoundImpactPlan, TagImpact
from release_workflow_lib.hashing import canonical_json_bytes, write_canonical_json
from tests.test_support import write_pe32
from warmup_memory import ProducerMemoryOwner


LOCK_PROBE_TIMED_OUT = 3


def lock_is_held_by_another_process(lock_path: Path) -> bool:
    """Try to take ``lock_path`` from a separate process; report whether it is already held."""
    script = textwrap.dedent(
        """
        import sys
        from pathlib import Path
        from idb_cache_locks import IdbCacheError, exclusive_file_lock

        try:
            with exclusive_file_lock(Path(sys.argv[1]), 0.0, wait_interval_seconds=0.0):
                pass
        except IdbCacheError:
            raise SystemExit(3)
        raise SystemExit(0)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(lock_path)],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in {0, LOCK_PROBE_TIMED_OUT}:
        raise AssertionError(f"lock probe failed: {result.returncode}: {result.stderr}")
    return result.returncode == LOCK_PROBE_TIMED_OUT


def cache_fixture(root: Path):
    workspace = root / "workspace"
    persisted = root / "persisted"
    persisted.mkdir()
    binary = write_pe32(workspace / "engine" / "hw.dll", b"cache-input")
    Path(f"{binary}.i64").write_bytes(b"primary-idb")
    Path(f"{binary}.i64.nam").write_bytes(b"names")
    runtime = {"kernel_version": "9.3"}
    binary_identity = build_binary_identity(
        workspace_root=workspace,
        module="engine",
        platform="windows",
        relative_path="engine/hw.dll",
    )
    identity = build_cache_identity(
        tag="game-1",
        ida_runtime=runtime,
        binaries=[binary_identity],
        warm_worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
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
        self.assertEqual(
            tuple(dict.fromkeys((*database_paths(binary), *database_lock_paths(binary)))),
            database_cleanup_paths(binary),
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
    def test_new_identity_uses_kernel_only_runtime_empty_args_and_canonical_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _workspace, _persisted, _binary, identity = cache_fixture(root)
            self.assertEqual({"kernel_version": "9.3"}, identity["ida_runtime"])
            self.assertEqual([], identity["normalized_ida_args"])
            alternate = root / "worker.py"
            alternate.write_text("worker\n", encoding="utf-8")
            with self.assertRaisesRegex(IdbCacheError, "canonical"):
                idb_cache.warm_worker_contract_sha256(alternate)

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

    def test_runtime_validator_accepts_only_current_or_complete_legacy_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            _workspace, _persisted, _binary, identity = cache_fixture(Path(temporary))
            with self.assertRaisesRegex(IdbCacheError, "unexpected or missing"):
                cache_key(
                    {
                        **identity,
                        "ida_runtime": {"kernel_version": "9.3", "processor": "metapc"},
                    }
                )
            with self.assertRaisesRegex(IdbCacheError, "normalized_ida_args"):
                publish_generation(
                    persisted_root=Path(temporary) / "persisted",
                    identity={**identity, "normalized_ida_args": ["-A"]},
                    workspace_root=Path(temporary) / "workspace",
                    run_id="run-1",
                    attempt=1,
                )

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
            linux = {
                **identity["binaries"][0],
                "module": "client",
                "platform": "linux",
                "path": "client/client.so",
            }
            with self.assertRaises(IdbCacheError):
                cache_key({**identity, "binaries": [linux, identity["binaries"][0]]})


class IdbCacheGenerationTests(unittest.TestCase):
    def test_legacy_schema_one_runtime_and_args_remain_readable_but_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, persisted, binary, current = cache_fixture(Path(temporary))
            legacy = {
                **current,
                "ida_runtime": {
                    "kernel_version": "9.3",
                    "processor": "metapc",
                    "bitness": 32,
                    "file_type": "PE",
                    "loader_name": "pe",
                    "loader_module_sha256": "1" * 64,
                    "plugins": [],
                },
                "normalized_ida_args": ["-A"],
            }
            legacy_key = cache_key(legacy)
            with self.assertRaisesRegex(IdbCacheError, "kernel-version-only"):
                publish_generation(
                    persisted_root=persisted,
                    identity=legacy,
                    workspace_root=workspace,
                    run_id="legacy",
                    attempt=1,
                )
            with patch.object(
                idb_cache,
                "validate_current_warm_identity",
                side_effect=idb_cache.validate_cache_identity,
            ):
                selection = publish_generation(
                    persisted_root=persisted,
                    identity=legacy,
                    workspace_root=workspace,
                    run_id="legacy",
                    attempt=1,
                )
            manifest = verify_selection(persisted_root=persisted, selection=selection)
            self.assertEqual(legacy_key, manifest["cache_key"])
            self.assertEqual(legacy, manifest["identity"])
            Path(f"{binary}.i64").unlink()
            restore_generation(persisted_root=persisted, selection=selection, workspace_root=workspace)
            self.assertTrue(Path(f"{binary}.i64").is_file())
            self.assertEqual([], prune_tag(persisted_root=persisted, tag="game-1"))

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


class IdbCacheWorkflowTests(unittest.TestCase):
    def _bound_repository(self, root: Path) -> tuple[Path, Path]:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        files = {
            "configs/config.yaml": b"gamevers:\n  - game-1\n",
            "configs/game-1.yaml": (
                b"modules:\n"
                b"  - name: engine\n"
                b"    module_windows: hw.dll\n"
                b"    skills:\n"
                b"      - name: find\n"
                b"        expected_output: Demo.{platform}.yaml\n"
                b"    symbols:\n"
                b"      - name: Demo\n"
                b"        category: func\n"
                b"  - name: client\n"
                b"    module_windows: client.dll\n"
                b"    skills:\n"
                b"      - name: other\n"
                b"        expected_output: Other.{platform}.yaml\n"
                b"    symbols:\n"
                b"      - name: Other\n"
                b"        category: func\n"
            ),
            "gamesymbol-impact.yaml": b"version: 1\nrules: []\n",
            "bin_artifacts/game-1/engine/Demo.windows.yaml": b"func_name: Demo\nfunc_va: '0x10'\n",
            "bin_artifacts/game-1/client/Other.windows.yaml": b"func_name: Other\nfunc_va: '0x20'\n",
        }
        for relative, raw in files.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "add",
                "configs",
                "gamesymbol-impact.yaml",
                "bin_artifacts",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "bound"], check=True)
        merge_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        write_pe32(repo / "bin" / "game-1" / "engine" / "hw.dll")
        write_pe32(repo / "bin" / "game-1" / "client" / "client.dll")
        digests = {
            "merge_config_index": hashlib.sha256(files["configs/config.yaml"]).hexdigest(),
            "merge_registry": hashlib.sha256(files["gamesymbol-impact.yaml"]).hexdigest(),
            "merge_config:game-1": hashlib.sha256(files["configs/game-1.yaml"]).hexdigest(),
            "merge_artifacts:game-1": hashlib.sha256(
                json.dumps(
                    [
                        {
                            "path": path.removeprefix("bin_artifacts/game-1/"),
                            "size": len(files[path]),
                            "sha256": hashlib.sha256(files[path]).hexdigest(),
                        }
                        for path in sorted(files)
                        if path.startswith("bin_artifacts/game-1/")
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
        action = TagImpact(
            "game-1",
            ("engine:windows:find",),
            ("engine/Demo.windows.yaml",),
            True,
            True,
            ("test",),
        )
        plan = BoundImpactPlan(merge_sha, merge_sha, merge_sha, None, None, (action,), digests)
        plan_path = root / "plan.json"
        plan_path.write_bytes(plan.canonical_bytes())
        return repo, plan_path

    def test_bound_warm_plan_selects_only_analysis_binary_pairs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, plan = self._bound_repository(root)
            groups = selected_binary_groups(repo_root=repo, plan_path=plan)
            self.assertEqual(1, len(groups))
            self.assertEqual(("game-1", "windows"), (groups[0].tag, groups[0].platform))
            self.assertEqual(["engine"], [record["module"] for record in groups[0].binaries])

    def test_persisted_workspace_must_be_plain_and_disjoint_from_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            persisted = root / "persisted"
            checkout.mkdir()
            persisted.mkdir()
            self.assertEqual(persisted.resolve(), validate_persisted_workspace(persisted, checkout))
            with self.assertRaises(IdbCacheSelectionError):
                validate_persisted_workspace(checkout, checkout)
            nested = checkout / "persisted"
            nested.mkdir()
            with self.assertRaises(IdbCacheSelectionError):
                validate_persisted_workspace(nested, checkout)

    def test_combined_selection_binds_plan_runtime_binaries_and_exact_generation(self):
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
            plan = {
                "plan_sha256": "a" * 64,
                "merge_sha": "b" * 40,
                "merge_bin_commit": "c" * 40,
            }
            group = SelectedBinaryGroup("game-1", "windows", workspace, tuple(identity["binaries"]))
            document = {
                "schema_version": CACHE_SELECTION_SCHEMA_VERSION,
                "cache_mode": "warm",
                "plan_sha256": plan["plan_sha256"],
                "merge_sha": plan["merge_sha"],
                "merge_bin_commit": plan["merge_bin_commit"],
                "entries": [
                    {
                        "tag": "game-1",
                        "platform": "windows",
                        "cache_key": selection["cache_key"],
                        "generation": selection["generation"],
                        "manifest_sha256": selection["manifest_sha256"],
                        "binaries": identity["binaries"],
                    }
                ],
            }
            self.assertEqual(
                document,
                validate_cache_selection(
                    document=document,
                    plan=plan,
                    groups=(group,),
                    identities={("game-1", "windows"): identity},
                    persisted_root=persisted,
                    raw=canonical_json_bytes(document),
                ),
            )
            with self.assertRaisesRegex(IdbCacheWorkflowError, "plan field"):
                validate_cache_selection(
                    document={**document, "plan_sha256": "d" * 64},
                    plan=plan,
                    groups=(group,),
                    identities={("game-1", "windows"): identity},
                    persisted_root=persisted,
                )

    def test_prepare_miss_then_hit_writes_and_restores_exact_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, plan = self._bound_repository(root)
            persisted = root / "persisted"
            persisted.mkdir()
            selection_path = root / "selection.json"
            selection_sha = root / "selection.sha256"
            warm_calls = []

            def fake_warm(**kwargs):
                self.assertFalse(lock_is_held_by_another_process(lock_root(persisted) / "game-1.lock"))
                self.assertTrue(lock_is_held_by_another_process(producer_lock_path(persisted)))
                warm_calls.append(kwargs["identity"])
                identity = kwargs["identity"]
                workspace = Path(kwargs["workspace_root"])
                for binary in identity["binaries"]:
                    Path(f"{workspace.joinpath(*Path(binary['path']).parts)}.i64").write_bytes(b"neutral-idb")

            common = {
                "repo_root": repo,
                "plan_path": plan,
                "merge_ref": "HEAD",
                "bindir": "bin",
                "persisted_root": persisted,
                "kernel_version": "9.3",
                "ida_python_executable": sys.executable,
                "run_id": "run-1",
                "attempt": 1,
                "max_concurrency": 2,
                "worker_timeout_seconds": 1,
                "producer_memory": ProducerMemoryOwner(None),
            }
            with patch("idb_cache_selection.warm_group", side_effect=fake_warm):
                first = prepare_cache_selection(
                    **common,
                    output_path=selection_path,
                    output_sha256_path=selection_sha,
                )
                second = prepare_cache_selection(
                    **common,
                    output_path=root / "selection-2.json",
                    output_sha256_path=root / "selection-2.sha256",
                )
            self.assertEqual(1, len(warm_calls))
            self.assertEqual(first["entries"], second["entries"])
            verified, _groups = verify_cache_selection_file(
                repo_root=repo,
                plan_path=plan,
                merge_ref="HEAD",
                bindir="bin",
                persisted_root=persisted,
                kernel_version="9.3",
                selection_path=selection_path,
                selection_sha256_path=selection_sha,
            )
            self.assertEqual(first, verified)
            binary = repo / "bin" / "game-1" / "engine" / "hw.dll"
            Path(f"{binary}.i64").write_bytes(b"selected-node-modification")
            restore_cache_selection(
                repo_root=repo,
                plan_path=plan,
                merge_ref="HEAD",
                bindir="bin",
                persisted_root=persisted,
                kernel_version="9.3",
                selection_path=selection_path,
                selection_sha256_path=selection_sha,
            )
            self.assertEqual(b"neutral-idb", Path(f"{binary}.i64").read_bytes())


class IdbCacheReadyWriteTests(unittest.TestCase):
    def test_ready_is_only_replaced_when_its_canonical_bytes_change(self):
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
            ready = persisted / "idb-cache" / "game-1" / "READY.json"
            self.assertEqual(canonical_json_bytes(first), ready.read_bytes())
            written = []
            original = idb_cache.write_canonical_json

            def spy(path, value):
                written.append(Path(path))
                return original(path, value)

            with patch.object(idb_cache, "write_canonical_json", side_effect=spy):
                probe_generation(persisted_root=persisted, identity=identity)
                publish_generation(
                    persisted_root=persisted,
                    identity=identity,
                    workspace_root=workspace,
                    run_id="run-1",
                    attempt=1,
                    published_at="2026-01-01T00:00:00Z",
                )
            self.assertNotIn(ready, written)
            Path(f"{binary}.i64").write_bytes(b"second generation database")
            second = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-2",
                attempt=1,
                published_at="2026-01-02T00:00:00Z",
            )
            self.assertEqual(canonical_json_bytes(second), ready.read_bytes())


class IdbCacheLockTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows byte-range lock compatibility")
    def test_lockfileex_and_msvcrt_lock_the_same_byte_range(self):
        import msvcrt

        script = textwrap.dedent(
            """
            import msvcrt
            import sys
            from pathlib import Path

            path = Path(sys.argv[1])
            with path.open("a+b") as handle:
                handle.seek(0, 2)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise SystemExit(3)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            """
        )
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "interop.lock"
            with exclusive_file_lock(lock_path, timeout_seconds=5):
                probe = subprocess.run(
                    [sys.executable, "-c", script, str(lock_path)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(LOCK_PROBE_TIMED_OUT, probe.returncode, probe.stderr)

            with lock_path.open("a+b") as handle:
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    self.assertTrue(lock_is_held_by_another_process(lock_path))
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

    def test_tag_lock_is_exclusive_across_processes_and_reports_its_description(self):
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary)
            lock_path = lock_root(persisted) / "game-1.lock"
            self.assertFalse(lock_is_held_by_another_process(lock_path))
            with tag_lock(persisted, "game-1", timeout_seconds=5.0):
                self.assertTrue(lock_is_held_by_another_process(lock_path))
                with self.assertRaisesRegex(IdbCacheLockError, "IDB cache tag lock for game-1"):
                    with tag_lock(persisted, "game-1", timeout_seconds=0.0):
                        pass
            # The lock file deliberately survives; only the open handle carried the lock.
            self.assertTrue(lock_path.is_file())
            self.assertFalse(lock_is_held_by_another_process(lock_path))

    def test_restore_cli_uses_the_selection_that_determined_the_tag_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            persisted = root / "persisted"
            workspace = root / "workspace"
            persisted.mkdir()
            workspace.mkdir()
            selection_path = root / "selection.json"

            def selection(tag: str) -> dict:
                return {
                    "schema_version": 1,
                    "tag": tag,
                    "cache_key": "a" * 64,
                    "generation": "generation-1",
                    "manifest_sha256": "b" * 64,
                }

            write_canonical_json(selection_path, selection("game-1"))
            restored = []

            @contextmanager
            def replace_selection_after_lock(_persisted_root, tag, **_kwargs):
                self.assertEqual("game-1", tag)
                write_canonical_json(selection_path, selection("game-2"))
                yield

            with (
                patch.object(idb_cache, "tag_lock", side_effect=replace_selection_after_lock),
                patch.object(
                    idb_cache,
                    "restore_generation",
                    side_effect=lambda **kwargs: restored.append(kwargs["selection"]),
                ),
            ):
                result = idb_cache.main(
                    [
                        "restore",
                        "-persisted-root",
                        str(persisted),
                        "-selection",
                        str(selection_path),
                        "-workspace-root",
                        str(workspace),
                    ]
                )
            self.assertEqual(0, result)
            self.assertEqual("game-1", restored[0]["tag"])

    def test_unbounded_lock_retries_only_explicit_contention(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "lock"
            contention = ctypes.WinError(33) if os.name == "nt" else BlockingIOError(11, "busy")
            with (
                patch("idb_cache_locks._acquire", side_effect=[contention, None]) as acquire,
                patch("idb_cache_locks._release"),
                patch("idb_cache_locks.time.sleep") as sleep,
                exclusive_file_lock(lock_path, timeout_seconds=None),
            ):
                pass
            self.assertEqual(2, acquire.call_count)
            sleep.assert_called_once()

            permission = ctypes.WinError(5) if os.name == "nt" else PermissionError(13, "denied")
            with (
                patch("idb_cache_locks._acquire", side_effect=permission),
                patch("idb_cache_locks.time.sleep") as sleep,
                self.assertRaisesRegex(IdbCacheLockError, "Unable to acquire"),
            ):
                with exclusive_file_lock(lock_path, timeout_seconds=None):
                    pass
            sleep.assert_not_called()

    def test_restore_holds_the_tag_lock_so_prune_cannot_run_concurrently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, persisted, binary, identity = cache_fixture(root)
            selection = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-1",
                attempt=1,
            )
            entry = {
                "tag": selection["tag"],
                "platform": "windows",
                "cache_key": selection["cache_key"],
                "generation": selection["generation"],
                "manifest_sha256": selection["manifest_sha256"],
                "binaries": identity["binaries"],
            }
            group = SelectedBinaryGroup("game-1", "windows", workspace, tuple(identity["binaries"]))
            lock_path = lock_root(persisted) / "game-1.lock"
            observed = []
            original = idb_cache_selection.restore_generation

            def spy(**kwargs):
                observed.append(lock_is_held_by_another_process(lock_path))
                return original(**kwargs)

            Path(f"{binary}.i64").write_bytes(b"finder modification")
            with patch.object(idb_cache_selection, "restore_generation", side_effect=spy):
                restore_selection_entries(entries=[entry], groups=(group,), persisted_root=persisted)
            self.assertEqual([True], observed)
            self.assertEqual(b"primary-idb", Path(f"{binary}.i64").read_bytes())
            self.assertFalse(lock_is_held_by_another_process(lock_path))


class IdbCacheReleaseTests(unittest.TestCase):
    CONFIG = (
        b"modules:\n"
        b"  - name: engine\n"
        b"    module_windows: hw.dll\n"
        b"    skills:\n"
        b"      - name: find\n"
        b"        expected_output: Demo.{platform}.yaml\n"
        b"    symbols:\n"
        b"      - name: Demo\n"
        b"        category: func\n"
        b"  - name: client\n"
        b"    module_windows: client.dll\n"
        b"    skills:\n"
        b"      - name: other\n"
        b"        expected_output: Other.{platform}.yaml\n"
        b"    symbols:\n"
        b"      - name: Other\n"
        b"        category: func\n"
    )
    BIN_COMMIT = "b" * 40

    def _release_repository(self, root: Path) -> tuple[Path, Path]:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        for relative, raw in {
            "configs/config.yaml": b"gamevers:\n  - game-1\n",
            "configs/game-1.yaml": self.CONFIG,
        }.items():
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(["git", "-C", str(repo), "add", "configs"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"160000,{self.BIN_COMMIT},bin"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "release source"], check=True)
        write_pe32(repo / "bin" / "game-1" / "engine" / "hw.dll")
        write_pe32(repo / "bin" / "game-1" / "client" / "client.dll")
        ida_root = root / "ida"
        (ida_root / "loaders").mkdir(parents=True)
        (ida_root / "loaders" / "pe.dll").write_bytes(b"pinned-pe-loader")
        return repo, ida_root

    @staticmethod
    def _fake_warm(**kwargs):
        identity = kwargs["identity"]
        workspace = Path(kwargs["workspace_root"])
        for record in identity["binaries"]:
            Path(f"{workspace.joinpath(*Path(record['path']).parts)}.i64").write_bytes(b"neutral-idb")

    def _common(self, repo: Path, persisted: Path, ida_root: Path) -> dict:
        return {
            "repo_root": repo,
            "bindir": "bin",
            "persisted_root": persisted,
            "kernel_version": "9.3",
            "source_sha": None,
        }

    def _prepare(self, repo: Path, persisted: Path, ida_root: Path, root: Path, name: str = "selection") -> dict:
        with patch("idb_cache_selection.warm_group", side_effect=self._fake_warm):
            return prepare_release_selection(
                **self._common(repo, persisted, ida_root),
                ida_python_executable=sys.executable,
                run_id="run-1",
                attempt=1,
                max_concurrency=2,
                worker_timeout_seconds=1,
                output_path=root / f"{name}.json",
                output_sha256_path=root / f"{name}.sha256",
                producer_memory=ProducerMemoryOwner(None),
            )

    def test_release_selection_binds_source_bin_and_every_configured_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, ida_root = self._release_repository(root)
            persisted = root / "persisted"
            persisted.mkdir()
            document = self._prepare(repo, persisted, ida_root, root)
            self.assertEqual(RELEASE_SELECTION_KEYS, set(document))
            self.assertEqual(RELEASE_SELECTION_SCHEMA_VERSION, document["schema_version"])
            self.assertEqual("warm", document["cache_mode"])
            self.assertEqual(self.BIN_COMMIT, document["bin_commit"])
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            self.assertEqual(head, document["source_sha"])
            self.assertEqual([("game-1", "windows")], [(e["tag"], e["platform"]) for e in document["entries"]])
            self.assertEqual(["client", "engine"], [record["module"] for record in document["entries"][0]["binaries"]])
            raw = (root / "selection.json").read_bytes()
            self.assertEqual(canonical_json_bytes(document), raw)
            self.assertEqual(
                f"{hashlib.sha256(raw).hexdigest()}\n", (root / "selection.sha256").read_text(encoding="ascii")
            )
            verified, _context = verify_release_selection_file(
                **self._common(repo, persisted, ida_root),
                selection_path=root / "selection.json",
                selection_sha256_path=root / "selection.sha256",
            )
            self.assertEqual(document, verified)

    def test_cache_hit_and_miss_produce_the_same_selection_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, ida_root = self._release_repository(root)
            persisted = root / "persisted"
            persisted.mkdir()
            warm_calls = []

            def counting_warm(**kwargs):
                warm_calls.append(kwargs["identity"]["tag"])
                return self._fake_warm(**kwargs)

            with patch("idb_cache_selection.warm_group", side_effect=counting_warm):
                first = prepare_release_selection(
                    **self._common(repo, persisted, ida_root),
                    ida_python_executable=sys.executable,
                    run_id="run-1",
                    attempt=1,
                    max_concurrency=2,
                    worker_timeout_seconds=1,
                    output_path=root / "first.json",
                    output_sha256_path=root / "first.sha256",
                    producer_memory=ProducerMemoryOwner(None),
                )
                second = prepare_release_selection(
                    **self._common(repo, persisted, ida_root),
                    ida_python_executable=sys.executable,
                    run_id="run-2",
                    attempt=1,
                    max_concurrency=2,
                    worker_timeout_seconds=1,
                    output_path=root / "second.json",
                    output_sha256_path=root / "second.sha256",
                    producer_memory=ProducerMemoryOwner(None),
                )
            self.assertEqual(["game-1"], warm_calls)
            self.assertEqual(first, second)

    def test_consumer_restores_the_bound_generation_after_ready_advances(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, ida_root = self._release_repository(root)
            persisted = root / "persisted"
            persisted.mkdir()
            document = self._prepare(repo, persisted, ida_root, root)
            entry = document["entries"][0]
            identity = verify_selection(persisted_root=persisted, selection=generation_selection(entry))["identity"]
            workspace = repo / "bin" / "game-1"
            for record in identity["binaries"]:
                Path(f"{workspace.joinpath(*Path(record['path']).parts)}.i64").write_bytes(b"newer-idb")
            advanced = publish_generation(
                persisted_root=persisted,
                identity=identity,
                workspace_root=workspace,
                run_id="run-9",
                attempt=1,
            )
            self.assertNotEqual(entry["generation"], advanced["generation"])
            self.assertEqual(
                advanced,
                json.loads((persisted / "idb-cache" / "game-1" / "READY.json").read_bytes()),
            )
            restore_release_selection(
                **self._common(repo, persisted, ida_root),
                selection_path=root / "selection.json",
                selection_sha256_path=root / "selection.sha256",
            )
            for record in identity["binaries"]:
                restored = Path(f"{workspace.joinpath(*Path(record['path']).parts)}.i64")
                self.assertEqual(b"neutral-idb", restored.read_bytes())

    def test_selection_is_rejected_on_source_bin_coverage_and_evidence_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, ida_root = self._release_repository(root)
            persisted = root / "persisted"
            persisted.mkdir()
            document = self._prepare(repo, persisted, ida_root, root)
            selection_path = root / "selection.json"
            sha_path = root / "selection.sha256"
            mutations = {
                "source": {**document, "source_sha": "c" * 40},
                "bin": {**document, "bin_commit": "d" * 40},
                "missing": {**document, "entries": []},
                "duplicate": {**document, "entries": [document["entries"][0], document["entries"][0]]},
                "binaries": {
                    **document,
                    "entries": [{**document["entries"][0], "binaries": document["entries"][0]["binaries"][:1]}],
                },
            }
            for name, mutated in mutations.items():
                with self.subTest(mutation=name):
                    write_canonical_json(selection_path, mutated)
                    digest = hashlib.sha256(selection_path.read_bytes()).hexdigest()
                    sha_path.write_text(f"{digest}\n", encoding="ascii", newline="\n")
                    with self.assertRaises((IdbCacheReleaseError, IdbCacheSelectionError)):
                        verify_release_selection_file(
                            **self._common(repo, persisted, ida_root),
                            selection_path=selection_path,
                            selection_sha256_path=sha_path,
                        )
            write_canonical_json(selection_path, document)
            sha_path.write_text(f"{'0' * 64}\n", encoding="ascii", newline="\n")
            with self.assertRaisesRegex(IdbCacheSelectionError, "SHA-256 evidence mismatch"):
                verify_release_selection_file(
                    **self._common(repo, persisted, ida_root),
                    selection_path=selection_path,
                    selection_sha256_path=sha_path,
                )

    def test_bound_source_sha_must_match_the_producer_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, ida_root = self._release_repository(root)
            persisted = root / "persisted"
            persisted.mkdir()
            with self.assertRaisesRegex(IdbCacheReleaseError, "drifted"):
                prepare_release_selection(
                    **{**self._common(repo, persisted, ida_root), "source_sha": "e" * 40},
                    ida_python_executable=sys.executable,
                    run_id="run-1",
                    attempt=1,
                    max_concurrency=2,
                    worker_timeout_seconds=1,
                    output_path=root / "selection.json",
                    output_sha256_path=root / "selection.sha256",
                    producer_memory=ProducerMemoryOwner(None),
                )


if __name__ == "__main__":
    unittest.main()
