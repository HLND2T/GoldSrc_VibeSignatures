from __future__ import annotations

import tempfile
import unittest
import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from release_workflow_lib.accepted_bin import (
    cleanup_legacy_accepted_yaml,
    durable_inventory,
    legacy_yaml_inventory,
    materialize_accepted_bin,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.locks import accepted_bin_lock_path, version_lock


class MaterializeAcceptedBinTests(unittest.TestCase):
    def _workspace(self, root: Path) -> tuple[Path, Path]:
        repo = root / "checkout"
        persisted = root / "persisted"
        (repo / "bin" / "hl-3248" / "engine").mkdir(parents=True)
        (repo / "bin" / "hl-3248" / "engine" / "tracked.txt").write_bytes(b"submodule tracked file")
        accepted = persisted / "bin" / "hl-3248" / "engine"
        accepted.mkdir(parents=True)
        (accepted / "hw.dll").write_bytes(b"accepted binary")
        (accepted / "symbol.yaml").write_bytes(b"func_name: legacy\n")
        (accepted / "SYMBOL.YML").write_bytes(b"func_name: legacy\n")
        (accepted / "hw.dll.i64").write_bytes(b"stale ida database")
        (accepted / "hw.dll.til").write_bytes(b"stale ida side file")
        return repo, persisted

    def test_overlays_binary_files_and_excludes_yaml_and_recoverable_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            result = materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-3248")
            target = repo / "bin" / "hl-3248" / "engine"
            self.assertTrue(result["materialized"])
            self.assertEqual(1, result["files"])
            self.assertEqual(durable_inventory(persisted / "bin" / "hl-3248")[1], result["hash"])
            self.assertEqual(b"accepted binary", (target / "hw.dll").read_bytes())
            self.assertEqual(b"submodule tracked file", (target / "tracked.txt").read_bytes())
            for excluded in ("symbol.yaml", "SYMBOL.YML", "hw.dll.i64", "hw.dll.til"):
                self.assertFalse((target / excluded).exists())

    def test_missing_persisted_tree_is_reported_without_touching_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            (repo / "bin" / "hl-9999").mkdir()
            result = materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-9999")
            self.assertEqual({"materialized": False, "gamever": "hl-9999", "files": 0, "hash": None}, result)
            self.assertEqual([], list((repo / "bin" / "hl-9999").iterdir()))

    def test_yaml_named_parent_does_not_hide_a_durable_binary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248" / "engine" / "metadata.yaml" / "payload.bin"
            source.parent.mkdir()
            source.write_bytes(b"durable payload")

            result = materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-3248")

            self.assertEqual(2, result["files"])
            target = repo / "bin" / "hl-3248" / "engine" / "metadata.yaml" / "payload.bin"
            self.assertEqual(b"durable payload", target.read_bytes())
            self.assertNotIn(
                "engine/metadata.yaml/payload.bin",
                {record["path"] for record in legacy_yaml_inventory(persisted / "bin" / "hl-3248")[0]},
            )

    def test_source_existence_is_checked_after_acquiring_gamever_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248"
            backup = persisted / "bin" / ".hl-3248.maintenance-backup"
            source.rename(backup)

            @contextmanager
            def finish_maintenance(_lock_path):
                backup.rename(source)
                yield

            with patch("release_workflow_lib.accepted_bin.version_lock", side_effect=finish_maintenance) as lock:
                result = materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-3248")
            lock.assert_called_once_with(accepted_bin_lock_path(persisted.resolve(), "hl-3248"))
            self.assertTrue(result["materialized"])

    def test_materialization_uses_per_gamever_binary_cache_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            lock_path = accepted_bin_lock_path(persisted.resolve(), "hl-3248")
            self.assertEqual(persisted.resolve() / "accepted-bin" / "locks" / "hl-3248.lock", lock_path)
            with version_lock(lock_path), self.assertRaisesRegex(ReleaseWorkflowError, "lock"):
                materialize_accepted_bin(repo_root=repo, persisted_root=persisted, gamever="hl-3248")

    def test_rejects_checkout_without_bin_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            _repo, persisted = self._workspace(Path(temporary))
            empty = Path(temporary) / "empty"
            empty.mkdir()
            with self.assertRaisesRegex(ReleaseWorkflowError, "checkout bin directory"):
                materialize_accepted_bin(repo_root=empty, persisted_root=persisted, gamever="hl-3248")

    def test_persisted_workspace_must_be_disjoint_and_must_not_traverse_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            overlapping = repo / "persisted"
            overlapping.mkdir()
            with self.assertRaisesRegex(ReleaseWorkflowError, "must not overlap"):
                materialize_accepted_bin(repo_root=repo, persisted_root=overlapping, gamever="hl-3248")

            linked = Path(temporary) / "persisted-link"
            try:
                os.symlink(persisted, linked, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(ReleaseWorkflowError, "link/reparse"):
                materialize_accepted_bin(repo_root=repo, persisted_root=linked, gamever="hl-3248")

    def test_legacy_yaml_cleanup_requires_verified_materialization_and_keeps_exact_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248"
            expected, expected_digest = legacy_yaml_inventory(source)
            result = cleanup_legacy_accepted_yaml(
                repo_root=repo,
                persisted_root=persisted,
                gamever="hl-3248",
                cutover_id="bin-artifacts-v1",
            )
            self.assertTrue(result["cleaned"])
            self.assertEqual(len(expected), result["files"])
            self.assertEqual(expected_digest, result["hash"])
            self.assertEqual([], legacy_yaml_inventory(source)[0])
            backup = Path(result["backup"])
            self.assertEqual(expected, legacy_yaml_inventory(backup)[0])
            self.assertTrue((backup / "legacy-yaml-inventory.json").is_file())
            self.assertEqual(b"accepted binary", (source / "engine" / "hw.dll").read_bytes())

            repeated = cleanup_legacy_accepted_yaml(
                repo_root=repo,
                persisted_root=persisted,
                gamever="hl-3248",
                cutover_id="bin-artifacts-v1",
            )
            self.assertFalse(repeated["cleaned"])
            self.assertEqual(0, repeated["files"])
            self.assertEqual(str(backup), repeated["backup"])
            self.assertEqual(expected_digest, repeated["hash"])

    def test_legacy_yaml_cleanup_recovers_a_verified_incoming_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            with patch.object(Path, "replace", side_effect=OSError("interrupted rename")):
                with self.assertRaisesRegex(ReleaseWorkflowError, "backup preparation failed"):
                    cleanup_legacy_accepted_yaml(
                        repo_root=repo,
                        persisted_root=persisted,
                        gamever="hl-3248",
                        cutover_id="bin-artifacts-v1",
                    )
            source = persisted / "bin" / "hl-3248"
            self.assertTrue(legacy_yaml_inventory(source)[0])
            result = cleanup_legacy_accepted_yaml(
                repo_root=repo,
                persisted_root=persisted,
                gamever="hl-3248",
                cutover_id="bin-artifacts-v1",
            )
            self.assertTrue(result["cleaned"])
            self.assertEqual([], legacy_yaml_inventory(source)[0])

    def test_legacy_yaml_cleanup_rebuilds_an_uncommitted_incoming_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            incoming = persisted / "accepted-bin" / "legacy-yaml-backups" / "bin-artifacts-v1" / ".hl-3248.incoming"
            (incoming / "engine").mkdir(parents=True)
            (incoming / "engine" / "partial.yaml").write_text("partial: true\n", encoding="utf-8")

            result = cleanup_legacy_accepted_yaml(
                repo_root=repo,
                persisted_root=persisted,
                gamever="hl-3248",
                cutover_id="bin-artifacts-v1",
            )

            self.assertTrue(result["cleaned"])
            self.assertFalse(incoming.exists())
            self.assertTrue((Path(result["backup"]) / "legacy-yaml-inventory.json").is_file())

    def test_legacy_yaml_cleanup_resumes_after_partial_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248"
            original_unlink = Path.unlink
            yaml_unlinks = 0

            def interrupt_second_yaml(path, *args, **kwargs):
                nonlocal yaml_unlinks
                if source in path.parents and path.suffix.lower() in {".yaml", ".yml"}:
                    yaml_unlinks += 1
                    if yaml_unlinks == 2:
                        raise OSError("interrupted deletion")
                return original_unlink(path, *args, **kwargs)

            with patch.object(Path, "unlink", interrupt_second_yaml):
                with self.assertRaisesRegex(ReleaseWorkflowError, "cleanup was interrupted"):
                    cleanup_legacy_accepted_yaml(
                        repo_root=repo,
                        persisted_root=persisted,
                        gamever="hl-3248",
                        cutover_id="bin-artifacts-v1",
                    )
            self.assertEqual(1, len(legacy_yaml_inventory(source)[0]))
            result = cleanup_legacy_accepted_yaml(
                repo_root=repo,
                persisted_root=persisted,
                gamever="hl-3248",
                cutover_id="bin-artifacts-v1",
            )
            self.assertTrue(result["cleaned"])
            self.assertEqual(1, result["files"])
            self.assertEqual([], legacy_yaml_inventory(source)[0])

    def test_legacy_yaml_cleanup_rejects_source_drift_after_partial_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248"
            original_unlink = Path.unlink
            yaml_unlinks = 0

            def interrupt_second_yaml(path, *args, **kwargs):
                nonlocal yaml_unlinks
                if source in path.parents and path.suffix.lower() in {".yaml", ".yml"}:
                    yaml_unlinks += 1
                    if yaml_unlinks == 2:
                        raise OSError("interrupted deletion")
                return original_unlink(path, *args, **kwargs)

            with patch.object(Path, "unlink", interrupt_second_yaml):
                with self.assertRaisesRegex(ReleaseWorkflowError, "cleanup was interrupted"):
                    cleanup_legacy_accepted_yaml(
                        repo_root=repo,
                        persisted_root=persisted,
                        gamever="hl-3248",
                        cutover_id="bin-artifacts-v1",
                    )
            remaining = legacy_yaml_inventory(source)[0]
            self.assertEqual(1, len(remaining))
            (source / remaining[0]["path"]).write_bytes(b"func_name: changed\n")

            with self.assertRaisesRegex(ReleaseWorkflowError, "new or differs"):
                cleanup_legacy_accepted_yaml(
                    repo_root=repo,
                    persisted_root=persisted,
                    gamever="hl-3248",
                    cutover_id="bin-artifacts-v1",
                )

    def test_legacy_yaml_cleanup_rejects_durable_inventory_drift_for_existing_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            result = cleanup_legacy_accepted_yaml(
                repo_root=repo,
                persisted_root=persisted,
                gamever="hl-3248",
                cutover_id="bin-artifacts-v1",
            )
            source = persisted / "bin" / "hl-3248"
            backup = Path(result["backup"])
            restored = backup / "engine" / "symbol.yaml"
            (source / "engine" / "symbol.yaml").write_bytes(restored.read_bytes())
            (source / "engine" / "hw.dll").write_bytes(b"changed accepted binary")

            with self.assertRaisesRegex(ReleaseWorkflowError, "durable inventory differs"):
                cleanup_legacy_accepted_yaml(
                    repo_root=repo,
                    persisted_root=persisted,
                    gamever="hl-3248",
                    cutover_id="bin-artifacts-v1",
                )

    def test_legacy_yaml_is_not_deleted_when_binary_materialization_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo, persisted = self._workspace(Path(temporary))
            source = persisted / "bin" / "hl-3248"
            before = legacy_yaml_inventory(source)[0]
            with (
                patch(
                    "release_workflow_lib.accepted_bin.materialize_accepted_bin",
                    side_effect=ReleaseWorkflowError("materialization failed"),
                ),
                self.assertRaisesRegex(ReleaseWorkflowError, "materialization failed"),
            ):
                cleanup_legacy_accepted_yaml(
                    repo_root=repo,
                    persisted_root=persisted,
                    gamever="hl-3248",
                    cutover_id="bin-artifacts-v1",
                )
            self.assertEqual(before, legacy_yaml_inventory(source)[0])


if __name__ == "__main__":
    unittest.main()
