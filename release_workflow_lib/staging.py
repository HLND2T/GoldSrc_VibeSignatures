"""Private release staging for a multi-gamever versioned build."""

from __future__ import annotations

import shutil
from pathlib import Path, PurePosixPath

from gamedata_candidate import GamedataCandidateError, verify_published_gamedata
from gamesymbol_snapshot_lib.operations import load_snapshot_context
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
    tracked_output_inventory,
    verify_inventory,
    write_canonical_json,
)
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    SCHEMA_VERSION,
    build_gamever_entry,
    build_tracked_manifest,
    load_tracked_manifest,
    parse_output_branch,
    require_build_id,
    require_sha,
    require_version,
    verify_tracked_outputs,
)

ABANDON_REASON_MAX_LENGTH = 500
PROMOTION_STATE_MARKERS = ("PROMOTION_STARTED", "PROMOTED.json", "PROMOTION_COMPLETE")
IDA_DATABASE_SUFFIXES = (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til")
RECOVERABLE_ANALYSIS_SUFFIXES = (*IDA_DATABASE_SUFFIXES, ".bsproj", ".binsync.json")
PRIVATE_FIELDS = {
    "schema_version",
    "version",
    "mode",
    "build_id",
    "source_sha",
    "workflow_run_url",
    "bin_manifest_sha256",
    "tracked_output_manifest_sha256",
    "gamevers",
    "repository",
    "output_branch",
    "pr_head_sha",
    "bin_files",
    "tracked_files",
}


def is_recoverable_analysis_path(path: Path) -> bool:
    return any(part.lower().endswith(RECOVERABLE_ANALYSIS_SUFFIXES) for part in Path(path).parts)


def ignore_recoverable_analysis_state(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if is_recoverable_analysis_path(Path(name))}


def _bin_inventory(stage_bin_root: Path, gamevers: list[str]) -> list[dict]:
    entries = []
    for gamever in gamevers:
        gamever_bin = contained_path(stage_bin_root, gamever)
        if not gamever_bin.is_dir():
            raise ReleaseWorkflowError(f"staged bin is missing for {gamever}: {gamever_bin}")
        for item in file_inventory(gamever_bin):
            entries.append({"gamever": gamever, **item})
    return sorted(entries, key=lambda item: (item["gamever"], item["path"]))


def verify_snapshot_binaries(document: dict, stage_bin: Path) -> int:
    binaries = document.get("binaries")
    if not binaries:
        return 0
    checked = 0
    for module, platforms in binaries.items():
        for platform, metadata in platforms.items():
            path = metadata.get("path")
            if not path:
                continue
            binary = contained_path(stage_bin, module, PurePosixPath(path).name)
            reject_reparse_components(stage_bin, binary)
            if not binary.is_file():
                raise ReleaseWorkflowError(f"snapshot binary is missing from staged bin: {module}/{platform}")
            if sha256_file(binary) != metadata["sha256"]:
                raise ReleaseWorkflowError(f"snapshot binary hash mismatch for {module}/{platform}")
            checked += 1
    return checked


def staging_directory(staging_root: Path, version: str, build_id: str) -> Path:
    version = require_version(version)
    staging_root = Path(staging_root)
    staging_root.mkdir(parents=True, exist_ok=True)
    target = contained_path(staging_root, version, build_id)
    reject_reparse_components(staging_root, target)
    return target


def _ready_builds(staging_root: Path, version: str) -> list[Path]:
    version_root = contained_path(Path(staging_root), version)
    if not version_root.is_dir():
        return []
    return sorted(path.parent for path in version_root.glob("*/READY") if path.is_file())


def assert_no_other_ready_build(staging_root: Path, version: str, build_id: str) -> None:
    active = [path for path in _ready_builds(staging_root, version) if path.name != build_id]
    if active:
        raise ReleaseWorkflowError(f"another ready staged build blocks {version}: {active[0]}")


def _validate_stage_request(*, staging_root: Path, repository: str, output_branch: str, version: str, build_id: str):
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    version = require_version(version)
    if parse_output_branch(output_branch) != version:
        raise ReleaseWorkflowError("output branch does not match VERSION")
    assert_no_other_ready_build(staging_root, version, build_id)
    stage_dir = staging_directory(staging_root, version, build_id)
    if stage_dir.exists():
        raise ReleaseWorkflowError(f"staging directory already exists: {stage_dir}")
    return version, stage_dir


def _write_stage_manifests(
    *,
    repo_root: Path,
    stage_dir: Path,
    stage_bin_root: Path,
    candidates: dict[str, Path],
    repository: str,
    output_branch: str,
    version: str,
    mode: str,
    build_id: str,
    source_sha: str,
    workflow_run_url: str,
    gamedata_sessions: dict[str, Path],
) -> dict:
    gamevers = sorted(candidates)
    bin_files = _bin_inventory(stage_bin_root, gamevers)
    tracked_files = tracked_output_inventory(repo_root, gamevers)
    entries = []
    for gamever in gamevers:
        candidate = candidates[gamever]
        analysis_config = (repo_root / "configs" / f"{gamever}.yaml").resolve()
        if not analysis_config.is_file():
            raise ReleaseWorkflowError(f"analysis config must be {analysis_config}")
        try:
            candidate_context = load_snapshot_context(candidate, analysis_config, gamever, repo_root / "bin")
        except Exception as exc:
            raise ReleaseWorkflowError(f"candidate snapshot provenance is invalid for {gamever}: {exc}") from exc
        verify_snapshot_binaries(candidate_context.document, stage_bin_root / gamever)
        try:
            gamedata = verify_published_gamedata(
                session_path=gamedata_sessions[gamever],
                repo_root=repo_root,
                gamever=gamever,
                candidate=candidate,
                analysis_config=analysis_config,
            )
        except GamedataCandidateError as exc:
            raise ReleaseWorkflowError(f"versioned gamedata provenance is invalid for {gamever}: {exc}") from exc
        entries.append(
            build_gamever_entry(
                gamever=gamever,
                candidate_sha256=sha256_file(candidate),
                analysis_config_path=f"configs/{gamever}.yaml",
                analysis_config_sha256=sha256_file(analysis_config),
                gamedata_path=gamedata["gamedata_path"],
                gamedata_manifest_sha256=gamedata["gamedata_manifest_sha256"],
                gamedata_inventory_sha256=inventory_sha256(
                    [item for item in tracked_files if item["path"].startswith(f"gamedata/{gamever}/")]
                ),
                generator_contract_sha256=gamedata["generator_contract_sha256"],
            )
        )
    tracked = build_tracked_manifest(
        version=version,
        mode=mode,
        build_id=build_id,
        source_sha=source_sha,
        workflow_run_url=workflow_run_url,
        bin_manifest_sha256=inventory_sha256(bin_files),
        tracked_output_manifest_sha256=inventory_sha256(tracked_files),
        gamevers=entries,
    )
    write_canonical_json(repo_root / "release-manifests" / f"{version}.json", tracked)
    pending = {
        **tracked,
        "repository": repository,
        "output_branch": output_branch,
        "pr_head_sha": None,
        "bin_files": bin_files,
        "tracked_files": tracked_files,
    }
    write_canonical_json(stage_dir / "manifest.json", pending)
    return pending


def stage_build(
    *,
    repo_root: Path,
    staging_root: Path,
    bin_sources: dict[str, Path],
    candidates: dict[str, Path],
    repository: str,
    output_branch: str,
    version: str,
    mode: str,
    build_id: str,
    source_sha: str,
    workflow_run_url: str,
    gamedata_sessions: dict[str, Path],
) -> dict:
    repo_root = Path(repo_root)
    staging_root = Path(staging_root)
    version, stage_dir = _validate_stage_request(
        staging_root=staging_root,
        repository=repository,
        output_branch=output_branch,
        version=version,
        build_id=build_id,
    )
    stage_bin_root = stage_dir / "bin"
    try:
        for gamever, bin_source in sorted(bin_sources.items()):
            reject_reparse_points(bin_source)
            target = stage_bin_root / gamever
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(bin_source, target, copy_function=shutil.copy2, ignore=ignore_recoverable_analysis_state)
        return _write_stage_manifests(
            repo_root=repo_root,
            stage_dir=stage_dir,
            stage_bin_root=stage_bin_root,
            candidates=candidates,
            repository=repository,
            output_branch=output_branch,
            version=version,
            mode=mode,
            build_id=build_id,
            source_sha=source_sha,
            workflow_run_url=workflow_run_url,
            gamedata_sessions=gamedata_sessions,
        )
    except Exception:
        if stage_dir.exists():
            remove_tree(stage_dir)
        raise


def finalize_stage(*, repo_root: Path, staging_root: Path, version: str, build_id: str, pr_head_sha: str) -> dict:
    pr_head_sha = require_sha(pr_head_sha, "PR head SHA")
    stage_dir = staging_directory(staging_root, version, build_id)
    reject_reparse_components(staging_root, stage_dir / "manifest.json")
    reject_reparse_components(staging_root, stage_dir / "READY")
    if (stage_dir / "READY").exists():
        pending = load_json_object(stage_dir / "manifest.json")
        if pending.get("pr_head_sha") != pr_head_sha:
            raise ReleaseWorkflowError("ready staging manifest has a different PR head SHA")
        return pending
    pending = load_json_object(stage_dir / "manifest.json")
    tracked_path = Path(repo_root) / "release-manifests" / f"{version}.json"
    tracked = load_tracked_manifest(tracked_path)
    if {key: pending.get(key) for key in tracked} != tracked:
        raise ReleaseWorkflowError("private and tracked release manifests disagree")
    verify_tracked_outputs(repo_root, tracked)
    gamevers = [entry["gamever"] for entry in tracked["gamevers"]]
    bin_files = _bin_inventory(stage_dir / "bin", gamevers)
    if bin_files != pending.get("bin_files"):
        raise ReleaseWorkflowError("staged bin inventory differs from pending manifest")
    if inventory_sha256(bin_files) != tracked["bin_manifest_sha256"]:
        raise ReleaseWorkflowError("staged bin manifest hash mismatch")
    pending["pr_head_sha"] = pr_head_sha
    write_canonical_json(stage_dir / "manifest.json", pending)
    ready_hash = sha256_file(stage_dir / "manifest.json")
    (stage_dir / "READY").write_text(f"{ready_hash}\n", encoding="ascii")
    return pending


def write_pr_index(*, staging_root: Path, pr_number: int, version: str, build_id: str, pr_head_sha: str) -> Path:
    if pr_number <= 0:
        raise ReleaseWorkflowError("PR number must be positive")
    pr_head_sha = require_sha(pr_head_sha, "PR head SHA")
    stage_dir = staging_directory(staging_root, version, build_id)
    if not (stage_dir / "READY").is_file():
        raise ReleaseWorkflowError("cannot index staging state before READY")
    pending = load_json_object(stage_dir / "manifest.json")
    if pending.get("pr_head_sha") != pr_head_sha:
        raise ReleaseWorkflowError("PR head SHA does not match private manifest")
    index = {
        "schema_version": SCHEMA_VERSION,
        "pr_number": pr_number,
        "version": version,
        "build_id": build_id,
        "pr_head_sha": pr_head_sha,
        "output_branch": pending["output_branch"],
    }
    index_path = contained_path(Path(staging_root), "pr-index", f"{pr_number}.json")
    reject_reparse_components(staging_root, index_path)
    if index_path.exists() and load_json_object(index_path) != index:
        raise ReleaseWorkflowError(f"PR index already exists with different identity: {index_path}")
    write_canonical_json(index_path, index)
    return index_path


def load_indexed_pending(staging_root: Path, pr_number: int, event_head_sha: str) -> tuple[dict, dict, Path]:
    event_head_sha = require_sha(event_head_sha, "event head SHA")
    index_path = contained_path(Path(staging_root), "pr-index", f"{pr_number}.json")
    reject_reparse_components(staging_root, index_path)
    index = load_json_object(index_path)
    expected_index_fields = {"schema_version", "pr_number", "version", "build_id", "pr_head_sha", "output_branch"}
    if set(index) != expected_index_fields:
        raise ReleaseWorkflowError("pending PR index has unexpected or missing fields")
    if index.get("pr_number") != pr_number or index.get("pr_head_sha") != event_head_sha:
        raise ReleaseWorkflowError("PR event identity does not match pending index")
    stage_dir = staging_directory(staging_root, index["version"], index["build_id"])
    reject_reparse_components(staging_root, stage_dir / "manifest.json")
    reject_reparse_components(staging_root, stage_dir / "READY")
    pending = load_json_object(stage_dir / "manifest.json")
    if set(pending) != PRIVATE_FIELDS:
        raise ReleaseWorkflowError("private pending manifest has unexpected or missing fields")
    if pending.get("schema_version") != index.get("schema_version"):
        raise ReleaseWorkflowError("private manifest schema does not match pending PR index")
    if pending.get("pr_head_sha") != event_head_sha or pending.get("output_branch") != index.get("output_branch"):
        raise ReleaseWorkflowError("private manifest identity does not match PR index")
    ready = stage_dir / "READY"
    if not ready.is_file() or ready.read_text(encoding="ascii").strip() != sha256_file(stage_dir / "manifest.json"):
        raise ReleaseWorkflowError("pending staging READY marker is invalid")
    return index, pending, stage_dir


def cleanup_unmerged(staging_root: Path, pr_number: int, event_head_sha: str) -> None:
    _index, _pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    _remove_indexed_pending(staging_root, pr_number, stage_dir)


def _remove_indexed_pending(staging_root: Path, pr_number: int, stage_dir: Path) -> None:
    index_path = contained_path(Path(staging_root), "pr-index", f"{pr_number}.json")
    reject_reparse_points(stage_dir)
    remove_tree(stage_dir)
    index_path.unlink()


def abandon_pending(
    *,
    staging_root: Path,
    persisted_root: Path,
    repository: str,
    output_branch: str,
    version: str,
    build_id: str,
    pr_number: int,
    event_head_sha: str,
    confirmation: str,
    reason: str,
) -> dict:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    version = require_version(version)
    build_id = require_build_id(build_id)
    if parse_output_branch(output_branch) != version:
        raise ReleaseWorkflowError("output branch does not match requested version")
    expected_confirmation = f"ABANDON {version}/{build_id}"
    if confirmation != expected_confirmation:
        raise ReleaseWorkflowError(f"confirmation must exactly equal {expected_confirmation!r}")
    reason = str(reason).strip()
    if not reason or len(reason) > ABANDON_REASON_MAX_LENGTH or any(char in reason for char in "\r\n"):
        raise ReleaseWorkflowError("abandon reason must be one non-empty line of at most 500 characters")

    index, pending, stage_dir = load_indexed_pending(staging_root, pr_number, event_head_sha)
    if (index.get("version"), index.get("build_id")) != (version, build_id):
        raise ReleaseWorkflowError("requested build identity does not match pending PR index")
    if pending.get("output_branch") != output_branch or index.get("output_branch") != output_branch:
        raise ReleaseWorkflowError("requested output branch does not match indexed pending state")
    if pending.get("repository") != repository:
        raise ReleaseWorkflowError("requested repository does not match private pending manifest")

    for marker in PROMOTION_STATE_MARKERS:
        marker_path = stage_dir / marker
        reject_reparse_components(staging_root, marker_path)
        if marker_path.exists():
            raise ReleaseWorkflowError(
                f"promotion state exists; recovery must resume instead of abandon: {marker_path}"
            )

    persisted_root = Path(persisted_root)
    accepted_root = contained_path(persisted_root, "bin")
    for suffix in ("incoming", "backup"):
        for gamever in [entry["gamever"] for entry in pending["gamevers"]]:
            recovery_path = contained_path(accepted_root, f".{gamever}.{build_id}.{suffix}")
            reject_reparse_components(persisted_root, recovery_path)
            if recovery_path.exists():
                raise ReleaseWorkflowError(f"promotion recovery path exists; refusing abandon: {recovery_path}")

    _remove_indexed_pending(staging_root, pr_number, stage_dir)
    return {
        "version": version,
        "build_id": build_id,
        "pr_number": pr_number,
        "pr_head_sha": require_sha(event_head_sha, "event head SHA"),
        "reason": reason,
    }


def cleanup_incomplete(staging_root: Path, version: str, build_id: str) -> bool:
    stage_dir = staging_directory(staging_root, version, build_id)
    if not stage_dir.exists() or (stage_dir / "READY").is_file():
        return False
    reject_reparse_points(stage_dir)
    remove_tree(stage_dir)
    return True
