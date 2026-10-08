import tempfile
import unittest
from pathlib import Path

from ci_s3_cache import parse_endpoint, prepare


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
    def test_fresh_external_staging_and_stable_relative_path(self):
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
            self.assertEqual(staging.resolve(), (checkout / second["cache-path"]).resolve())
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
