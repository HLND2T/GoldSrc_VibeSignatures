import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release_publish as publisher

NOTES = "## English\n- Fixed symbols.\n\n## 中文\n- 修复符号。\n"


class NotesPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.notes = self.root / "notes.md"
        self.notes.write_text(NOTES, encoding="utf-8")
        self.asset = self.root / "asset.7z"
        self.asset.write_bytes(b"payload")
        self.tag = None
        self.release = None
        self.calls = []
        self.fail_upload = False
        self.drift = None
        self.kwargs = {
            "repository": "owner/repo",
            "repo_root": self.root,
            "bundle_root": self.root,
            "version": "v20260910a",
            "source_sha": "a" * 40,
            "build_id": "123",
            "workflow_run_url": "https://github.com/owner/repo/actions/runs/123",
            "cache_selection_sha256": "b" * 64,
            "notes_file": self.notes,
        }
        manifest = {k: self.kwargs[k] for k in ("source_sha", "build_id", "workflow_run_url")}
        for name, settings in (
            ("verify_release_bundle", {"return_value": manifest}),
            ("remote_state", {"side_effect": lambda *args: (copy.deepcopy(self.tag), copy.deepcopy(self.release))}),
            ("_release_assets", {"return_value": (self.asset,)}),
            ("_run", {"side_effect": self.run_command}),
        ):
            mock = patch.object(publisher, name, **settings)
            mock.start()
            self.addCleanup(mock.stop)

    def run_command(self, args):
        self.calls.append(args)
        if args[1] == "api":
            self.tag = {"object": {"type": "commit", "sha": "a" * 40}}
        elif args[2] == "create":
            self.release = {
                "id": 1,
                "tag_name": self.kwargs["version"],
                "draft": True,
                "assets": [],
                "body": Path(args[args.index("--notes-file") + 1]).read_text(encoding="utf-8"),
            }
        elif args[2] == "upload":
            if self.fail_upload:
                raise publisher.ReleasePublishError("upload failed")
            self.release["assets"].append(
                {
                    "name": self.asset.name,
                    "size": self.asset.stat().st_size,
                    "digest": "sha256:" + publisher._sha256_file(self.asset),
                }
            )
            if self.drift == "tag":
                self.tag["object"]["sha"] = "c" * 40
            elif self.drift == "body":
                self.release["body"] += "manual edit"
            elif self.drift == "published":
                self.release["draft"] = False
            elif self.drift == "identity":
                self.release["id"] = 2
        elif args[2] == "edit":
            if "--notes-file" in args:
                self.release["body"] = Path(args[args.index("--notes-file") + 1]).read_text(encoding="utf-8")
            if "--draft=false" in args:
                self.release["draft"] = False
        else:
            raise AssertionError(args)

    def test_missing_invalid_and_forged_notes_never_create_tag(self):
        for notes in (None, "", "English only", NOTES + "<!-- gsvibe-release-identity: {} -->"):
            with self.subTest(notes=notes):
                if notes is None:
                    self.notes.unlink()
                else:
                    self.notes.write_text(notes, encoding="utf-8")
                with self.assertRaises((publisher.ReleasePublishError, OSError, ValueError)):
                    publisher.publish_release(**self.kwargs)
                self.assertEqual([], self.calls)

    def test_new_release_upload_retry_and_published_noop(self):
        self.fail_upload = True
        with self.assertRaisesRegex(publisher.ReleasePublishError, "upload failed"):
            publisher.publish_release(**self.kwargs)
        self.assertTrue(self.release["draft"])
        self.fail_upload = False
        self.notes.write_text(NOTES + "Updated.\n", encoding="utf-8")
        self.assertEqual("resume", publisher.publish_release(**self.kwargs))
        self.assertFalse(self.release["draft"])
        self.assertTrue(self.release["body"].startswith(NOTES + "Updated.\n"))
        self.assertEqual(1, sum(args[1:3] == ["release", "create"] for args in self.calls))
        before = copy.deepcopy(self.release)
        self.calls.clear()
        self.notes.unlink()
        self.assertEqual("published", publisher.publish_release(**self.kwargs))
        self.assertEqual([], self.calls)
        self.assertEqual(before, self.release)

    def test_remote_drift_blocks_publication(self):
        for drift in ("tag", "body", "published", "identity"):
            with self.subTest(drift=drift):
                self.tag = self.release = None
                self.calls.clear()
                self.drift = drift
                with self.assertRaises(publisher.ReleasePublishError):
                    publisher.publish_release(**self.kwargs)
                self.assertFalse(any("--draft=false" in args for args in self.calls))

    def test_draft_asset_conflict_never_overwrites(self):
        publisher.publish_release(**self.kwargs)
        self.release["draft"] = True
        self.release["assets"][0]["digest"] = "sha256:" + "f" * 64
        self.calls.clear()
        with self.assertRaisesRegex(publisher.ReleasePublishError, "cannot be overwritten"):
            publisher.publish_release(**self.kwargs)
        self.assertFalse(any("upload" in args or "--draft=false" in args for args in self.calls))
