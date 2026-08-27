from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.validation import validate_build_input

REPOSITORY = "HLND2T/GoldSrc_VibeSignatures"
VERSION = "v20260825a"


def _run_git(root: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _build_repo(root: Path) -> str:
    _run_git(root, "init", "-q")
    _run_git(root, "config", "user.email", "test@example.com")
    _run_git(root, "config", "user.name", "Test")
    (root / "configs").mkdir(parents=True)
    (root / "configs" / "config.yaml").write_text("gamevers:\n  - hl-10210\n", encoding="utf-8")
    _run_git(root, "add", "-A")
    _run_git(root, "commit", "-q", "-m", "source")
    _run_git(root, "branch", "-M", "main")
    return _run_git(root, "rev-parse", "HEAD")


def _call(root: Path, source_sha: str, *, allow_existing_tag: bool = False) -> None:
    previous = os.getcwd()
    os.chdir(root)
    try:
        validate_build_input(
            repository=REPOSITORY,
            version=VERSION,
            source_sha=source_sha,
            mode="new",
            default_ref="main",
            allow_existing_tag=allow_existing_tag,
        )
    finally:
        os.chdir(previous)


class ValidateBuildInputTagTriggerTests(unittest.TestCase):
    def test_new_accepts_absent_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha = _build_repo(root)
            _call(root, source_sha)  # no tag; must not raise

    def test_new_rejects_existing_tag_without_allow_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha = _build_repo(root)
            _run_git(root, "tag", VERSION, source_sha)
            with self.assertRaisesRegex(ReleaseWorkflowError, r"mode=new requires tag"):
                _call(root, source_sha)

    def test_new_accepts_tag_pointing_at_source_sha_when_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha = _build_repo(root)
            _run_git(root, "tag", VERSION, source_sha)
            _call(root, source_sha, allow_existing_tag=True)  # must not raise

    def test_new_rejects_tag_pointing_elsewhere_even_when_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_sha = _build_repo(root)
            _run_git(root, "tag", VERSION, source_sha)
            _run_git(root, "commit", "--allow-empty", "-q", "-m", "advance")
            newer_sha = _run_git(root, "rev-parse", "HEAD")
            self.assertNotEqual(source_sha, newer_sha)
            _run_git(root, "tag", "-f", VERSION, newer_sha)
            with self.assertRaisesRegex(ReleaseWorkflowError, r"point at SOURCE_SHA"):
                _call(root, source_sha, allow_existing_tag=True)


if __name__ == "__main__":
    unittest.main()
