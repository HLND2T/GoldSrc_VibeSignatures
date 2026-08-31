from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from release_workflow_lib.accepted_bin import durable_inventory, materialize_accepted_bin
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


if __name__ == "__main__":
    unittest.main()
