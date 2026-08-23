from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from gamesymbol_snapshot_lib.metadata import write_metadata
from gamesymbol_snapshot_lib.operations import pack_snapshot
from release_workflow_lib.content import (
    CONFIG_CONTRACT_PATHS,
    RELEASE_TOOL_CONTRACT_PATHS,
    build_content_manifest,
    verify_content_manifest,
)
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.git_objects import GitObjectRepository
from release_workflow_lib.hashing import canonical_json_bytes
from release_workflow_lib.manifest import parse_content_manifest_bytes
from release_workflow_lib.shadow import run_shadow_verification
from tests.test_support import write_config, write_pe32
from update_gamedata import generate_gamedata

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ".github/workflows/release-shadow.yml"


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout.decode("utf-8").strip()


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


def create_release_repository(root: Path, tags: tuple[str, ...] = ("game-1",)) -> str:
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "test@example.com")
    git(root, "config", "user.name", "Test")
    source_paths = set(CONFIG_CONTRACT_PATHS) | set(RELEASE_TOOL_CONTRACT_PATHS)
    for relative in sorted(source_paths):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / relative, destination)
    workflow = root / WORKFLOW_PATH
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("name: Release shadow\n", encoding="utf-8")
    working = root.parent / f"{root.name}-binary-work"
    (root / "configs").mkdir()
    for tag in tags:
        config = write_config(root / "configs" / f"{tag}.yaml", both_platforms=False)
        config.write_bytes(config.read_bytes().replace(b"\r\n", b"\n"))
        binary = write_pe32(working / "bin" / tag / "engine" / "hw.dll", tag.encode("ascii"))
        snapshot = root / "gamesymbols" / f"{tag}.yaml"
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        pack_snapshot(
            tag,
            working / "bin",
            config,
            snapshot,
            last_publish_time="2026-01-02T03:04:05Z",
        )
        self_check = snapshot.read_bytes()
        if not binary.is_file() or not self_check:
            raise AssertionError("Invalid release test fixture")
        write_metadata(
            snapshot_path=snapshot,
            config_path=config,
            game_version=tag,
            output_path=root / "gamesymbols" / f"{tag}.metadata.yaml",
        )
        generate_gamedata(
            gamever=tag,
            snapshot_path=snapshot,
            config_path=config,
            modules_dir=root / "gamedata-generators",
            output_root=root / "gamedata" / tag,
        )
    seed = commit_all(root, "seed release inputs")
    git(root, "update-index", "--add", "--cacheinfo", "160000", seed, "bin")
    git(root, "commit", "-q", "-m", "bind bin gitlink")
    return git(root, "rev-parse", "HEAD")


def build(root: Path, tag: str = "game-1") -> dict:
    return build_content_manifest(
        repo=GitObjectRepository(root),
        source_ref="main",
        tag=tag,
        repository_id=12345,
        workflow_repository="owner/repository",
        workflow_path=WORKFLOW_PATH,
        workflow_ref="main",
    )


class ReleaseContentManifestTests(unittest.TestCase):
    def test_manifest_is_canonical_repeatable_and_binds_exact_git_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            create_release_repository(root)
            first = build(root)
            second = build(root)
            self.assertEqual(first, second)
            raw = canonical_json_bytes(first)
            self.assertEqual(first, parse_content_manifest_bytes(raw))
            self.assertEqual(git(root, "rev-parse", "HEAD"), first["source_sha"])
            self.assertEqual(git(root, "rev-parse", "HEAD:bin"), first["bin_gitlink_sha"])
            self.assertRegex(first["tracked_content_inventory_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("release-manifests", raw.decode("utf-8"))

    def test_content_inventory_excludes_tracked_release_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            create_release_repository(root)
            first = build(root)
            tracked = root / "release-manifests" / "game-1.json"
            tracked.parent.mkdir()
            tracked.write_bytes(canonical_json_bytes(first))
            git(root, "add", "release-manifests/game-1.json")
            git(root, "commit", "-q", "-m", "add release manifest")
            second = build(root)
            self.assertNotEqual(first["source_sha"], second["source_sha"])
            self.assertEqual(
                first["tracked_content_inventory_sha256"],
                second["tracked_content_inventory_sha256"],
            )

    def test_payload_tamper_extra_file_and_non_regular_mode_fail_closed(self):
        mutations = ("metadata", "config", "gamedata", "extra", "mode", "generator")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "repository"
                create_release_repository(root)
                if mutation == "metadata":
                    path = root / "gamesymbols" / "game-1.metadata.yaml"
                    path.write_bytes(path.read_bytes() + b"\n")
                elif mutation == "config":
                    path = root / "configs" / "game-1.yaml"
                    path.write_bytes(path.read_bytes() + b"# drift\n")
                elif mutation == "gamedata":
                    path = root / "gamedata" / "game-1" / "gamedata-manifest.json"
                    document = json.loads(path.read_bytes())
                    document["candidate_sha256"] = "0" * 64
                    path.write_bytes(canonical_json_bytes(document))
                elif mutation == "extra":
                    (root / "gamedata" / "game-1" / "extra.txt").write_text("extra\n", encoding="utf-8")
                elif mutation == "mode":
                    path = root / "gamesymbols" / "game-1.yaml"
                    git(root, "update-index", "--chmod=+x", path.relative_to(root).as_posix())
                else:
                    generator = root / "gamedata-generators" / "demo" / "gamedata.py"
                    generator.parent.mkdir(parents=True)
                    generator.write_text(
                        "MODULE_NAME = 'demo'\n"
                        "OUTPUT_PATHS = ('value.txt',)\n"
                        "def update(store, output_dir):\n"
                        "    (output_dir / 'value.txt').write_text('value', encoding='utf-8')\n",
                        encoding="utf-8",
                    )
                if mutation == "mode":
                    git(root, "commit", "-q", "-m", "tamper mode")
                else:
                    commit_all(root, f"tamper {mutation}")
                with self.assertRaises((ReleaseWorkflowError, ValueError)):
                    build(root)

    def test_manifest_schema_and_default_branch_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            create_release_repository(root)
            document = build(root)
            raw = canonical_json_bytes(document)
            for mutation in (
                {**document, "unknown": True},
                {key: value for key, value in document.items() if key != "candidate_sha256"},
                {**document, "candidate_sha256": "SHA256:" + "0" * 64},
            ):
                with self.subTest(keys=tuple(mutation)), self.assertRaises(ReleaseWorkflowError):
                    parse_content_manifest_bytes(canonical_json_bytes(mutation))
            with self.assertRaises(ReleaseWorkflowError):
                parse_content_manifest_bytes(raw.rstrip(b"\n"))
            (root / "unrelated.txt").write_text("drift\n", encoding="utf-8")
            commit_all(root, "default branch drift")
            with self.assertRaises(ReleaseWorkflowError):
                verify_content_manifest(
                    repo=GitObjectRepository(root),
                    default_ref="main",
                    manifest_raw=raw,
                    repository_id=12345,
                    workflow_repository="owner/repository",
                    workflow_path=WORKFLOW_PATH,
                    workflow_ref="main",
                )


class ReleaseShadowTests(unittest.TestCase):
    def test_shadow_verifies_three_new_tags_without_mutating_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            tags = ("game-1", "game-2", "game-3")
            source_sha = create_release_repository(root, tags)
            output = Path(temporary) / "evidence"
            before = git(root, "status", "--porcelain=v1")
            evidence = run_shadow_verification(
                repo=GitObjectRepository(root),
                default_ref="main",
                tags=tags,
                repository_id=12345,
                workflow_repository="owner/repository",
                workflow_path=WORKFLOW_PATH,
                workflow_ref="main",
                output_dir=output,
            )
            self.assertEqual(source_sha, evidence["source_sha"])
            self.assertEqual(["new", "new", "new"], [item["mode_decision"] for item in evidence["results"]])
            self.assertTrue((output / "shadow-evidence.json").is_file())
            self.assertEqual(before, git(root, "status", "--porcelain=v1"))


if __name__ == "__main__":
    unittest.main()
