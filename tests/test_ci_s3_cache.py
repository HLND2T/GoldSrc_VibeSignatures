import shutil
import tempfile
import unittest
from pathlib import Path

from ci_s3_cache import parse_endpoint, prepare, write_outputs


class EndpointTests(unittest.TestCase):
    def test_http_custom_port(self):
        self.assertEqual({"endpoint": "HZVM", "port": "8333", "insecure": "true"}, parse_endpoint("http://HZVM:8333"))

    def test_https_and_default_ports(self):
        self.assertEqual(
            {"endpoint": "cache.local", "port": "443", "insecure": "false"}, parse_endpoint("https://cache.local/")
        )
        self.assertEqual("80", parse_endpoint("http://cache.local")["port"])
        self.assertEqual("8443", parse_endpoint("https://cache.local:8443")["port"])

    def test_invalid_origins(self):
        for value in (
            "",
            "HZVM:8333",
            "ftp://host",
            "http://u:p@host",
            "http://host/path",
            "http://host?",
            "http://host#",
            "http://host:0",
            "http://host:65536",
            "http://host:",
            "http://host:abc",
            "http://host\n",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_endpoint(value)


class StagingTests(unittest.TestCase):
    def test_windows_snapshot_import_can_restore_exact_generation_and_lease_on_linux_layout(self):
        from idb_cache import IdbCacheError, publish_generation
        from idb_cache_leases import new_lease
        from idb_cache_selection import restore_selection_entries
        from idb_cache_workflow import SelectedBinaryGroup
        from tests.test_idb_cache import cache_fixture, pin_document

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary_root, persisted, binary, identity = cache_fixture(root)
            selection = publish_generation(
                persisted_root=persisted, identity=identity, workspace_root=binary_root, run_id="old-windows", attempt=1
            )
            entry = {**selection, "platform": "windows", "binaries": identity["binaries"]}
            document = {"entries": [entry], "lease": new_lease(repository="owner/repo", run_id="1", attempt=1)}
            digest = pin_document(persisted, document)
            checkout = root / "runner" / "checkout"
            checkout.mkdir(parents=True)
            windows = prepare(checkout, "owner/repo", "Windows")
            legacy_key = windows["restore-prefixes"].splitlines()[1] + "1-1"
            objects = {legacy_key: persisted}
            linux = prepare(checkout, "owner/repo", "Linux")
            matched = next(
                key for prefix in linux["restore-prefixes"].splitlines() for key in objects if key.startswith(prefix)
            )
            shutil.copytree(objects[matched], linux["persisted-root"], dirs_exist_ok=True)
            # A new producer publishes the verified legacy store under the shared
            # run key, and a consumer on another checkout receives that exact store.
            shared_key = linux["prefix"] + "-idb-2-1"
            published = root / "published"
            shutil.copytree(linux["persisted-root"], published)
            objects[shared_key] = published
            consumer_checkout = root / "consumer" / "checkout"
            consumer_checkout.mkdir(parents=True)
            consumer = prepare(consumer_checkout, "owner/repo", "Linux")
            shutil.copytree(objects[shared_key], consumer["persisted-root"], dirs_exist_ok=True)
            Path(f"{binary}.i64").write_bytes(b"local modifications")
            restore_selection_entries(
                entries=[entry],
                groups=(SelectedBinaryGroup("game-1", "windows", binary_root, tuple(identity["binaries"])),),
                persisted_root=Path(consumer["persisted-root"]),
                lease=document["lease"],
                selection_sha256=digest,
            )
            self.assertEqual(b"primary-idb", Path(f"{binary}.i64").read_bytes())
            with self.assertRaises(IdbCacheError):
                restore_selection_entries(
                    entries=[entry],
                    groups=(SelectedBinaryGroup("game-1", "windows", binary_root, tuple(identity["binaries"])),),
                    persisted_root=Path(consumer["persisted-root"]),
                    lease=document["lease"],
                    selection_sha256=digest,
                )

    def test_shared_namespace_and_ordered_legacy_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory) / "checkout"
            checkout.mkdir()
            layouts = [prepare(checkout, "Owner/Repo", platform) for platform in ("Windows", "Linux", "macOS")]
            self.assertEqual(layouts[0], layouts[1])
            self.assertEqual(layouts[0], layouts[2])
            prefix = layouts[0]["prefix"]
            self.assertTrue(prefix.endswith("-shared"))
            base = prefix.removesuffix("shared")
            self.assertEqual(
                [f"{base}{platform}-idb-" for platform in ("shared", "windows", "linux", "macos")],
                layouts[0]["restore-prefixes"].splitlines(),
            )

    def test_multiline_outputs_use_delimiters(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            write_outputs({"prefix": "shared", "restore-prefixes": "shared-idb-\nwindows-idb-"}, output)
            lines = output.read_text(encoding="utf-8").splitlines()
            self.assertEqual("prefix=shared", lines[0])
            delimiter = lines[1].split("<<", 1)[1]
            self.assertEqual(["shared-idb-", "windows-idb-", delimiter], lines[2:])

    def test_fresh_external_staging_and_stable_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            sentinel = checkout / "keep"
            sentinel.write_text("keep")
            first = prepare(checkout, "Owner/Repo", "Windows")
            staging = Path(first["persisted-root"])
            self.assertEqual(root.resolve(), staging.parent.resolve())
            (staging / "old-cache").write_text("stale")
            second = prepare(checkout, "owner/repo", "Windows")
            self.assertEqual(first, second)
            self.assertEqual([], list(staging.iterdir()))
            self.assertEqual("keep", sentinel.read_text())
            # actions-cache rejects relative patterns, so cache-path must be absolute.
            self.assertTrue(Path(second["cache-path"]).is_absolute())
            self.assertEqual(str(staging), second["cache-path"])
            self.assertEqual(second["persisted-root"], second["cache-path"])
            self.assertNotIn("/", first["prefix"])
            self.assertNotEqual(first["prefix"], prepare(checkout, "Owner/Other", "Windows")["prefix"])

    def test_reject_link_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            staging = Path(prepare(checkout, "owner/repo", "Windows")["persisted-root"])
            staging.rmdir()
            target = root / "target"
            target.mkdir()
            sentinel = target / "keep"
            sentinel.write_text("keep")
            try:
                staging.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(ValueError):
                prepare(checkout, "owner/repo", "Windows")
            self.assertEqual("keep", sentinel.read_text())


if __name__ == "__main__":
    unittest.main()
