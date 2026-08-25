"""Merge-time verification and promotion for a multi-gamever versioned release."""

from __future__ import annotations

import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.filesystem import remove_tree
from release_workflow_lib.hashing import (
    contained_path,
    file_inventory,
    inventory_sha256,
    load_json_object,
    reject_reparse_components,
    reject_reparse_points,
    sha256_file,
    validate_output_paths,
    verify_inventory,
    write_canonical_json,
)
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    SCHEMA_VERSION,
    load_tracked_manifest,
    parse_output_branch,
    require_build_id,
    require_sha,
    require_version,
    verify_tracked_outputs,
)
from release_workflow_lib.staging import _bin_inventory, load_indexed_pending

COMPLETION_SCHEMA_VERSION = 1
COMPLETION_FIELDS = {
    "schema_version",
    "version",
    "build_id",
    "pr_number",
    "pr_head_sha",
    "output_merge_sha",
    "bin_manifest_sha256",
    "tracked_output_manifest_sha256",
    "release_provenance_sha256",
}


def _git_output(arguments: list[str]) -> str:
    result = subprocess.run(["git", *arguments], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ReleaseWorkflowError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def verify_output_pr(
    *,
    repo_root: Path,
    repository: str,
    head_repository: str,
    author: str,
    branch: str,
    base_sha: str,
    head_sha: str,
) -> dict:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    base_sha = require_sha(base_sha, "PR base SHA")
    require_sha(head_sha, "PR head SHA")
    if repository != head_repository:
        raise ReleaseWorkflowError("generated-output PR must originate from the base repository")
    if author != "github-actions[bot]":
        raise ReleaseWorkflowError("generated-output PR author is not github-actions[bot]")
    version = parse_output_branch(branch)
    paths = [line for line in _git_output(["diff", "--name-only", base_sha, head_sha, "--"]).splitlines() if line]
    manifest = load_tracked_manifest(Path(repo_root) / "release-manifests" / f"{version}.json")
    validate_output_paths(paths, [entry["gamever"] for entry in manifest["gamevers"]], version)
    if manifest["source_sha"] != base_sha or manifest["version"] != version:
        raise ReleaseWorkflowError("output PR is stale or its manifest identity does not match the branch")
    verify_tracked_outputs(repo_root, manifest)
    return manifest


def verify_promotion(
    *,
    repo_root: Path,
    staging_root: Path,
    repository: str,
    head_repository: str,
    author: str,
    branch: str,
    base_branch: str,
    default_branch: str,
    pr_number: int,
    event_head_sha: str,
    merge_sha: str,
) -> dict:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    merge_sha = require_sha(merge_sha, "OUTPUT_MERGE_SHA")
    if repository != head_repository:
        raise ReleaseWorkflowError("promotion requires a same-repository PR")
    if author != "github-actions[bot]":
        raise ReleaseWorkflowError("promotion requires github-actions[bot] as PR author")
    if base_branch != default_branch:
        raise ReleaseWorkflowError("generated-output PR base is not the default branch")
    version = parse_output_branch(branch)
    index, pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    if index["output_branch"] != branch or index["version"] != version:
        raise ReleaseWorkflowError("pull request branch does not match pending index")
    if pending.get("repository") != repository:
        raise ReleaseWorkflowError("private manifest repository identity mismatch")
    parents = _git_output(["rev-list", "--parents", "-n", "1", merge_sha]).split()
    if len(parents) != 3:
        raise ReleaseWorkflowError("promotion requires a two-parent merge commit")
    base_parent_sha, merged_head_sha = parents[1:]
    if merged_head_sha != event_head_sha:
        raise ReleaseWorkflowError("merge second parent does not match PR head SHA")
    head_parents = _git_output(["rev-list", "--parents", "-n", "1", event_head_sha]).split()
    if len(head_parents) != 2 or head_parents[1] != pending["source_sha"]:
        raise ReleaseWorkflowError("generated-output commit is not directly based on SOURCE_SHA")
    if not _is_ancestor(pending["source_sha"], base_parent_sha):
        raise ReleaseWorkflowError("merge first parent must descend from SOURCE_SHA")
    paths = [
        line for line in _git_output(["diff", "--name-only", base_parent_sha, merge_sha, "--"]).splitlines() if line
    ]
    gamevers = [entry["gamever"] for entry in pending["gamevers"]]
    validate_output_paths(paths, gamevers, version)
    tracked = load_tracked_manifest(Path(repo_root) / "release-manifests" / f"{version}.json")
    if {key: pending.get(key) for key in tracked} != tracked:
        raise ReleaseWorkflowError("tracked and private manifests disagree during promotion")
    tracked_files = verify_tracked_outputs(repo_root, tracked)
    if tracked_files != pending.get("tracked_files"):
        raise ReleaseWorkflowError("tracked output inventory differs from pending build")
    bin_files = _bin_inventory(stage_dir / "bin", gamevers)
    if bin_files != pending.get("bin_files"):
        raise ReleaseWorkflowError("staged bin inventory differs from pending build")
    if inventory_sha256(bin_files) != tracked["bin_manifest_sha256"]:
        raise ReleaseWorkflowError("staged bin hash differs from tracked manifest")
    return {**tracked, "stage_dir": str(stage_dir), "output_merge_sha": merge_sha}


def reconstruct_workspace(repo_root: Path, stage_dir: Path, version: str) -> Path:
    repo_root = Path(repo_root).resolve()
    stage_dir = Path(stage_dir)
    reject_reparse_components(stage_dir, stage_dir)
    source = contained_path(stage_dir, "bin")
    reject_reparse_points(source)
    for gamever_dir in sorted(path for path in source.iterdir() if path.is_dir()):
        target = contained_path(repo_root, "bin", gamever_dir.name)
        if target.exists():
            reject_reparse_points(target)
            remove_tree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(gamever_dir, target, copy_function=shutil.copy2)
    return source


@contextmanager
def _version_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except OSError as exc:
        raise ReleaseWorkflowError(f"unable to acquire per-version promotion lock: {lock_path}") from exc
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def promote_bin(*, persisted_root: Path, stage_dir: Path, version: str, build_id: str) -> dict:
    version = require_version(version)
    build_id = require_build_id(build_id)
    persisted_root = Path(persisted_root).resolve()
    reject_reparse_components(persisted_root, persisted_root)
    stage_dir = Path(stage_dir)
    reject_reparse_components(stage_dir, stage_dir)
    pending = load_json_object(stage_dir / "manifest.json")
    if (pending.get("version"), pending.get("build_id")) != (version, build_id):
        raise ReleaseWorkflowError("promotion request does not match private pending manifest")
    gamevers = [entry["gamever"] for entry in pending["gamevers"]]
    bin_files = _bin_inventory(stage_dir / "bin", gamevers)
    expected_hash = pending.get("bin_manifest_sha256")
    if inventory_sha256(bin_files) != expected_hash:
        raise ReleaseWorkflowError("staged bin failed verification before promotion")

    accepted_root = contained_path(persisted_root, "bin")
    reject_reparse_components(persisted_root, accepted_root)
    accepted_root.mkdir(parents=True, exist_ok=True)
    lock_path = contained_path(persisted_root, "release-staging", "locks", f"{version}.lock")
    promoted = {}
    with _version_lock(lock_path):
        started_path = stage_dir / "PROMOTION_STARTED"
        reject_reparse_components(stage_dir, started_path)
        write_canonical_json(started_path, {"schema_version": SCHEMA_VERSION, "version": version, "build_id": build_id})
        for gamever in gamevers:
            source = contained_path(stage_dir, "bin", gamever)
            target = contained_path(accepted_root, gamever)
            incoming = contained_path(accepted_root, f".{gamever}.{build_id}.incoming")
            backup = contained_path(accepted_root, f".{gamever}.{build_id}.backup")
            gamever_files = [item for item in bin_files if item["gamever"] == gamever]
            if target.is_dir() and inventory_sha256(gamever_files) == inventory_sha256(file_inventory(target)):
                continue
            promoted[gamever] = _swap_verified_bin(source, target, incoming, backup, gamever_files)
    return {"version": version, "build_id": build_id, "promoted": promoted}


def _swap_verified_bin(source: Path, target: Path, incoming: Path, backup: Path, expected_files: list[dict]) -> bool:
    if backup.exists():
        raise ReleaseWorkflowError(f"promotion backup already exists while accepted bin differs: {backup}")
    if incoming.exists():
        reject_reparse_points(incoming)
        remove_tree(incoming)
    shutil.copytree(source, incoming, copy_function=shutil.copy2)
    expected_hash = inventory_sha256(expected_files)
    if inventory_sha256(file_inventory(incoming)) != expected_hash:
        remove_tree(incoming)
        raise ReleaseWorkflowError("incoming accepted-bin directory failed verification")
    moved_old = False
    try:
        if target.exists():
            os.replace(target, backup)
            moved_old = True
        os.replace(incoming, target)
    except OSError as exc:
        if moved_old and not target.exists() and backup.exists():
            os.replace(backup, target)
        raise ReleaseWorkflowError(f"transactional accepted-bin swap failed: {exc}") from exc
    return moved_old


def finalize_promotion(
    *,
    staging_root: Path,
    pr_number: int,
    event_head_sha: str,
    output_merge_sha: str,
    release_provenance: Path,
) -> dict:
    staging_root = Path(staging_root)
    _index, pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    release_provenance = Path(release_provenance)
    if not release_provenance.is_file():
        raise ReleaseWorkflowError("release provenance is missing before promotion completion")
    record = {
        "schema_version": COMPLETION_SCHEMA_VERSION,
        "version": pending["version"],
        "build_id": pending["build_id"],
        "pr_number": pr_number,
        "pr_head_sha": pending["pr_head_sha"],
        "output_merge_sha": require_sha(output_merge_sha, "OUTPUT_MERGE_SHA"),
        "bin_manifest_sha256": pending["bin_manifest_sha256"],
        "tracked_output_manifest_sha256": pending["tracked_output_manifest_sha256"],
        "release_provenance_sha256": sha256_file(release_provenance),
    }
    write_canonical_json(stage_dir / "PROMOTION_COMPLETE", record)
    completed_path = contained_path(staging_root, "completed", pending["version"], f"{pending['build_id']}.json")
    write_canonical_json(completed_path, record)
    index_path = contained_path(staging_root, "pr-index", f"{pr_number}.json")
    index_path.unlink()
    return record


def _matching_pr_indexes(staging_root: Path, version: str, build_id: str) -> list[Path]:
    index_root = contained_path(staging_root, "pr-index")
    if not index_root.exists():
        return []
    reject_reparse_points(index_root)
    return [
        path
        for path in index_root.glob("*.json")
        if (load_json_object(path).get("version"), load_json_object(path).get("build_id")) == (version, build_id)
    ]


def _validate_completion_record(record: dict, version: str, build_id: str) -> dict:
    if set(record) != COMPLETION_FIELDS or record.get("schema_version") != COMPLETION_SCHEMA_VERSION:
        raise ReleaseWorkflowError("completion record has unexpected fields or schema")
    if (record.get("version"), record.get("build_id")) != (require_version(version), require_build_id(build_id)):
        raise ReleaseWorkflowError("completion record identity mismatch")
    require_sha(record.get("pr_head_sha", ""), "completion PR head SHA")
    require_sha(record.get("output_merge_sha", ""), "completion output merge SHA")
    if not isinstance(record.get("pr_number"), int) or record["pr_number"] <= 0:
        raise ReleaseWorkflowError("completion record has an invalid PR number")
    for field in ("bin_manifest_sha256", "tracked_output_manifest_sha256", "release_provenance_sha256"):
        if len(record.get(field, "")) != 64 or any(char not in "0123456789abcdef" for char in record[field]):
            raise ReleaseWorkflowError(f"completion record has an invalid {field}")
    return record


def cleanup_completed(*, staging_root: Path, persisted_root: Path, version: str, build_id: str) -> dict:
    staging_root = Path(staging_root)
    persisted_root = Path(persisted_root).resolve()
    if (persisted_root / "release-staging").resolve() != staging_root.resolve():
        raise ReleaseWorkflowError("staging_root must be persisted_root/release-staging")
    completion_path = contained_path(staging_root, "completed", version, f"{build_id}.json")
    reject_reparse_components(staging_root, completion_path)
    record = _validate_completion_record(load_json_object(completion_path), version, build_id)
    if _matching_pr_indexes(staging_root, version, build_id):
        raise ReleaseWorkflowError("completed stage still has a matching PR index")
    stage_dir = contained_path(staging_root, version, build_id)
    trash_dir = contained_path(staging_root, "cleanup-trash", version, build_id)
    lock_path = contained_path(staging_root, "locks", f"{version}.lock")
    resumed = False
    with _version_lock(lock_path):
        if stage_dir.exists() and trash_dir.exists():
            raise ReleaseWorkflowError("both completed stage and cleanup trash exist")
        if stage_dir.exists():
            reject_reparse_points(stage_dir)
            trash_dir.parent.mkdir(parents=True, exist_ok=True)
            os.replace(stage_dir, trash_dir)
        elif trash_dir.exists():
            reject_reparse_points(trash_dir)
            resumed = True
        else:
            return {"status": "already-absent", "version": version, "build_id": build_id}
    remove_tree(trash_dir)
    return {"status": "resumed" if resumed else "removed", "version": version, "build_id": build_id}


def list_completed(staging_root: Path) -> list[dict]:
    completed_root = contained_path(Path(staging_root), "completed")
    if not completed_root.exists():
        return []
    reject_reparse_points(completed_root)
    records = []
    for path in sorted(completed_root.glob("*/*.json")):
        record = load_json_object(path)
        records.append(_validate_completion_record(record, path.parent.name, path.stem))
    return records
