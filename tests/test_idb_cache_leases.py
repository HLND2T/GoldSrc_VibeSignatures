from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import idb_cache
import idb_cache_leases as leases
import idb_cache_selection as selections
from idb_cache_locks import producer_lock, tag_lock
from idb_cache_workflow import SelectedBinaryGroup
from release_workflow_lib.hashing import canonical_json_bytes, write_canonical_json
from tests.test_idb_cache import cache_fixture
from tests.test_support import write_elf32
from warmup_memory import ProducerMemoryOwner


class SelectionLeaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace, self.persisted, self.binary, self.identity = cache_fixture(self.root)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        clock = patch.object(leases, "utc_now", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.group = SelectedBinaryGroup("game-1", "windows", self.workspace, tuple(self.identity["binaries"]))
        self.selected = self.publish(self.identity, "historical")

    def publish(self, identity, run_id, age_days=60):
        with producer_lock(self.persisted), tag_lock(self.persisted, identity["tag"]):
            return idb_cache.publish_generation(
                persisted_root=self.persisted,
                identity=identity,
                workspace_root=self.workspace,
                run_id=run_id,
                attempt=1,
                published_at=(self.now - timedelta(days=age_days)).strftime(leases.TIME_FORMAT),
            )

    def prepare(self, *, run_id="run-a", attempt=1, groups=None, identities=None, seal=True):
        lease = leases.new_lease(repository="owner/repo", run_id=run_id, attempt=attempt)
        with (
            producer_lock(self.persisted),
            patch.object(selections, "prune_tag", side_effect=lambda **kw: idb_cache.prune_tag(now=self.now, **kw)),
        ):
            entries = selections.prepare_selection_entries(
                groups=groups or (self.group,),
                identities=identities or {("game-1", "windows"): self.identity},
                persisted_root=self.persisted,
                run_id=run_id,
                attempt=attempt,
                lease=lease,
                ida_python_executable=sys.executable,
                max_concurrency=2,
                worker_timeout_seconds=1,
                producer_memory=ProducerMemoryOwner(None),
            )
        document = {"schema_version": 2, "entries": entries, "lease": lease}
        if seal:
            selections.seal_selection_leases(document=document, persisted_root=self.persisted)
        return document

    def lease_path(self, document, tag="game-1"):
        return self.persisted / leases.CACHE_DIRECTORY_NAME / tag / "leases" / f"{document['lease']['lease_id']}.json"

    def digest(self, document):
        return hashlib.sha256(canonical_json_bytes(document)).hexdigest()

    def restore(self, document, groups=None):
        selections.restore_selection_entries(
            entries=document["entries"],
            groups=groups or (self.group,),
            persisted_root=self.persisted,
            lease=document["lease"],
            selection_sha256=self.digest(document),
        )

    def prune(self, **kwargs):
        with producer_lock(self.persisted), tag_lock(self.persisted, "game-1"):
            return idb_cache.prune_tag(persisted_root=self.persisted, tag="game-1", now=self.now, **kwargs)

    def make_old_selection_collectible(self):
        for index in range(3):
            self.publish(
                {**self.identity, "ida_runtime": {"kernel_version": f"other-{index}"}},
                f"other-{index}-{int(self.now.timestamp())}",
                50 - index,
            )

    def test_preparing_and_sealed_pins_survive_other_process_prune_and_restore(self):
        for seal in (False, True):
            with self.subTest(seal=seal):
                document = self.prepare(run_id=f"run-{seal}", seal=seal)
                self.make_old_selection_collectible()
                result = subprocess.run(
                    [sys.executable, "idb_cache.py", "prune", "-persisted-root", str(self.persisted), "-tag", "game-1"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual(self.selected["generation"], document["entries"][0]["generation"])
                idb_cache.verify_selection(persisted_root=self.persisted, selection=self.selected)
                if not seal:
                    selections.seal_selection_leases(document=document, persisted_root=self.persisted)
                consumer = self.root / f"consumer-{seal}"
                (consumer / "engine").mkdir(parents=True)
                shutil.copyfile(self.binary, consumer / "engine" / "hw.dll")
                selection_path = self.root / "selection.json"
                write_canonical_json(selection_path, document)
                script = """
import hashlib, json, sys
from pathlib import Path
from idb_cache_selection import restore_selection_entries
from idb_cache_workflow import SelectedBinaryGroup
raw = Path(sys.argv[1]).read_bytes()
document = json.loads(raw)
entry = document['entries'][0]
group = SelectedBinaryGroup(entry['tag'], entry['platform'], Path(sys.argv[3]), tuple(entry['binaries']))
restore_selection_entries(entries=document['entries'], groups=(group,), persisted_root=sys.argv[2],
                          lease=document['lease'], selection_sha256=hashlib.sha256(raw).hexdigest())
"""
                result = subprocess.run(
                    [sys.executable, "-c", script, str(selection_path), str(self.persisted), str(consumer)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual(b"primary-idb", (consumer / "engine" / "hw.dll.i64").read_bytes())
                self.assertFalse(self.lease_path(document).exists())

    def test_same_generation_has_independent_attempts_and_idempotent_release(self):
        first = self.prepare(attempt=1)
        second = self.prepare(attempt=2)
        self.assertEqual(first["entries"], second["entries"])
        self.assertEqual("run-a", first["lease"]["run_id"])
        self.assertIn("historical", first["entries"][0]["generation"])
        self.make_old_selection_collectible()
        self.restore(first)
        with tag_lock(self.persisted, "game-1"):
            leases.release_lease(
                tag_root=self.lease_path(first).parent.parent, lease=first["lease"], selection_sha256=self.digest(first)
            )
        self.assertTrue(self.lease_path(second).exists())
        self.assertNotIn(self.selected["generation"], self.prune())
        self.restore(second)
        self.assertIn(self.selected["generation"], self.prune())

    def test_partial_restore_keeps_all_platform_pins_until_retry_succeeds(self):
        linux_binary = write_elf32(self.workspace / "engine" / "hw.so", b"linux-input")
        Path(f"{linux_binary}.i64").write_bytes(b"linux-idb")
        linux = idb_cache.build_cache_identity(
            tag="game-1",
            ida_runtime={"kernel_version": "9.3"},
            binaries=[
                idb_cache.build_binary_identity(
                    workspace_root=self.workspace, module="engine", platform="linux", relative_path="engine/hw.so"
                )
            ],
            warm_worker_path=Path(idb_cache.__file__).with_name("idb_warm_worker.py"),
        )
        self.publish(linux, "historical-linux")
        groups = (self.group, SelectedBinaryGroup("game-1", "linux", self.workspace, tuple(linux["binaries"])))
        document = self.prepare(
            groups=groups, identities={("game-1", "windows"): self.identity, ("game-1", "linux"): linux}
        )
        self.assertEqual(
            ["linux", "windows"],
            [ref["platform"] for ref in json.loads(self.lease_path(document).read_bytes())["references"]],
        )
        actual_restore = selections.restore_generation

        def fail_second(**kwargs):
            if kwargs["selection"]["generation"] == self.selected["generation"]:
                raise OSError("injected copy failure")
            return actual_restore(**kwargs)

        with patch.object(selections, "restore_generation", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "injected copy failure"):
                self.restore(document, groups)
        self.make_old_selection_collectible()
        removed = self.prune()
        for entry in document["entries"]:
            self.assertNotIn(entry["generation"], removed)
        self.restore(document, groups)
        self.assertFalse(self.lease_path(document).exists())

    def test_expiry_has_clock_grace_and_reclaims_abandoned_prepares(self):
        for seal in (False, True):
            document = self.prepare(run_id=f"abandoned-{seal}", seal=seal)
            self.make_old_selection_collectible()
            self.now += leases.LEASE_LIFETIME
            self.assertNotIn(self.selected["generation"], self.prune())
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "expired.*Re-run the full workflow"):
                self.restore(document)
            self.now += leases.CLOCK_SKEW_ALLOWANCE
            self.assertIn(self.selected["generation"], self.prune())
            self.assertFalse(self.lease_path(document).exists())
            self.selected = self.publish(self.identity, f"historical-{seal}")

    def test_failed_later_tag_keeps_earlier_tag_pinned(self):
        other_identity = {**self.identity, "tag": "game-2"}
        self.publish(other_identity, "historical-game-2")
        groups = (
            self.group,
            SelectedBinaryGroup("game-2", "windows", self.workspace, tuple(other_identity["binaries"])),
        )
        document = self.prepare(
            groups=groups,
            identities={
                ("game-1", "windows"): self.identity,
                ("game-2", "windows"): other_identity,
            },
        )
        actual_restore = selections.restore_generation

        def fail_last_tag(**kwargs):
            if kwargs["selection"]["tag"] == "game-2":
                raise OSError("second tag unavailable")
            return actual_restore(**kwargs)

        with patch.object(selections, "restore_generation", side_effect=fail_last_tag):
            with self.assertRaisesRegex(OSError, "second tag unavailable"):
                self.restore(document, groups)
        for tag in ("game-1", "game-2"):
            self.assertTrue(self.lease_path(document, tag).exists())
        self.restore(document, groups)
        for tag in ("game-1", "game-2"):
            self.assertFalse(self.lease_path(document, tag).exists())

    def test_atomic_write_scratch_is_not_a_pin_and_is_eventually_reclaimed(self):
        document = self.prepare()
        directory = self.lease_path(document).parent
        scratch = directory / f".{document['lease']['lease_id']}.json.{'a' * 32}.tmp"
        scratch.write_bytes(b"interrupted partial JSON")
        self.make_old_selection_collectible()
        self.assertNotIn(self.selected["generation"], self.prune())
        self.assertTrue(scratch.exists())
        stale_time = (self.now - leases.LEASE_LIFETIME).timestamp()
        os.utime(scratch, (stale_time, stale_time))
        self.assertNotIn(self.selected["generation"], self.prune())
        self.assertFalse(scratch.exists())

    def test_sealing_requires_the_complete_exact_reference_set(self):
        document = self.prepare(seal=False)
        tampered = copy.deepcopy(document)
        tampered["entries"][0]["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "preparing lease"):
            selections.seal_selection_leases(document=tampered, persisted_root=self.persisted)
        self.assertIsNone(json.loads(self.lease_path(document).read_bytes())["selection_sha256"])

    def test_missing_released_and_unsealed_leases_fail_before_copy(self):
        document = self.prepare(seal=False)
        with patch.object(selections, "restore_generation") as copy_files:
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "binding mismatch"):
                self.restore(document)
            copy_files.assert_not_called()

        selections.seal_selection_leases(document=document, persisted_root=self.persisted)
        self.restore(document)
        with patch.object(selections, "restore_generation") as copy_files:
            with self.assertRaisesRegex(idb_cache.IdbCacheError, "missing or released.*Re-run the full workflow"):
                self.restore(document)
            copy_files.assert_not_called()

    def test_shared_validation_requires_a_live_lease(self):
        document = self.prepare()
        arguments = {
            "entries": document["entries"],
            "identities": {("game-1", "windows"): self.identity},
            "persisted_root": self.persisted,
            "lease": document["lease"],
            "selection_sha256": self.digest(document),
        }
        selections.validate_selection_entries(**arguments)
        self.restore(document)
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "missing or released"):
            selections.validate_selection_entries(**arguments)
        arguments["lease"] = None
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "unexpected fields"):
            selections.validate_selection_entries(**arguments)

    def test_seal_owner_and_digest_cannot_be_rebound(self):
        document = self.prepare()
        selections.seal_selection_leases(document=document, persisted_root=self.persisted)
        for field, value in (("run_id", "someone-else"), ("attempt", 2), ("repository", "other/repo")):
            changed = copy.deepcopy(document)
            changed["lease"][field] = value
            with self.subTest(field=field), self.assertRaises(idb_cache.IdbCacheError):
                selections.seal_selection_leases(document=changed, persisted_root=self.persisted)
            with self.assertRaises(idb_cache.IdbCacheError):
                self.restore(changed)
        changed = {**document, "extra": "different digest"}
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "different selection"):
            selections.seal_selection_leases(document=changed, persisted_root=self.persisted)
        with tag_lock(self.persisted, "game-1"), self.assertRaises(idb_cache.IdbCacheError):
            leases.release_lease(
                tag_root=self.lease_path(document).parent.parent, lease=document["lease"], selection_sha256="0" * 64
            )
        self.assertTrue(self.lease_path(document).exists())

    def test_malformed_or_unreadable_lease_blocks_every_prune_deletion(self):
        document = self.prepare()
        self.make_old_selection_collectible()
        tag_root = self.lease_path(document).parent.parent
        incoming = tag_root / "generations" / ".incoming-abandoned"
        incoming.mkdir()
        stale_time = (self.now - timedelta(days=3)).timestamp()
        os.utime(incoming, (stale_time, stale_time))
        lease_path = self.lease_path(document)
        original = lease_path.read_bytes()
        record = json.loads(original)
        mutations = [
            b"broken",
            original.replace(b'"attempt":1', b'"attempt":NaN'),
            original.replace(b'"run_id":"run-a"', b'"run_id":"\\ud800"'),
            original.replace(b'"schema_version":1', b'"schema_version":999'),
            original.replace(b'"tag":', b'"tag":"wrong","tag":'),
        ]
        for raw in mutations:
            lease_path.write_bytes(raw)
            with self.assertRaises(idb_cache.IdbCacheError):
                self.prune()
            self.assertTrue(incoming.exists())
            idb_cache.verify_selection(persisted_root=self.persisted, selection=self.selected)
        lease_path.write_bytes(original)
        real_read = Path.read_bytes

        def denied(path):
            if path == lease_path:
                raise PermissionError("injected denied")
            return real_read(path)

        with patch.object(Path, "read_bytes", denied), self.assertRaisesRegex(idb_cache.IdbCacheError, "denied"):
            self.prune()
        self.assertTrue(incoming.exists())
        self.assertEqual(document["lease"], record["lease"])

    def test_lease_paths_and_timestamps_reject_tampering(self):
        document = self.prepare()
        for field, value in (
            ("lease_id", "../escape"),
            ("run_id", "../escape"),
            ("attempt", True),
            ("expires_at", "9999-12-31T00:00:00Z"),
            ("created_at", "not-a-time"),
        ):
            changed = copy.deepcopy(document)
            changed["lease"][field] = value
            with self.subTest(field=field), self.assertRaises(idb_cache.IdbCacheError):
                self.restore(changed)
        lease_path = self.lease_path(document)
        outside = self.root / "outside.json"
        outside.write_bytes(lease_path.read_bytes())
        lease_path.unlink()
        try:
            lease_path.symlink_to(outside)
        except OSError as exc:
            self.skipTest(f"Symlinks unavailable: {exc}")
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "plain file"):
            self.prune()
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "plain file"):
            self.restore(document)
        self.assertTrue(outside.exists())

    def test_future_clock_record_blocks_prune_but_archive_ignores_live_policy(self):
        document = self.prepare()
        path = self.lease_path(document)
        record = json.loads(path.read_bytes())
        future = self.now + timedelta(days=100)
        record["lease"].update(
            created_at=future.strftime(leases.TIME_FORMAT),
            expires_at=(future + leases.LEASE_LIFETIME).strftime(leases.TIME_FORMAT),
        )
        write_canonical_json(path, record)
        with self.assertRaisesRegex(idb_cache.IdbCacheError, "runner clocks"):
            self.prune()
        self.assertEqual(record["lease"], leases.validate_lease_descriptor(record["lease"]))
        # Historical evidence remains valid if a future version changes retention duration.
        record["lease"]["expires_at"] = (future + timedelta(days=2)).strftime(leases.TIME_FORMAT)
        self.assertEqual(record["lease"], leases.validate_lease_descriptor(record["lease"]))

    def test_pin_write_failure_aborts_prepare_before_prune(self):
        with (
            patch.object(leases, "write_canonical_json", side_effect=OSError("pin write failed")),
            patch.object(selections, "prune_tag") as prune,
        ):
            with self.assertRaisesRegex(OSError, "pin write failed"):
                self.prepare()
            prune.assert_not_called()

    def test_legacy_prune_cannot_reach_new_payload_namespace(self):
        document = self.prepare()
        # Model a legacy pruner operating only in its original, unleased namespace.
        legacy_root = self.persisted / "idb-cache" / "game-1"
        new_root = self.lease_path(document).parent.parent
        shutil.copytree(new_root / "generations", legacy_root / "generations")
        self.make_old_selection_collectible()
        with patch.object(idb_cache, "CACHE_DIRECTORY_NAME", "idb-cache"):
            self.assertIn(self.selected["generation"], self.prune(keep_latest=0))
        self.restore(document)
        self.assertEqual(b"primary-idb", Path(f"{self.binary}.i64").read_bytes())


if __name__ == "__main__":
    unittest.main()
