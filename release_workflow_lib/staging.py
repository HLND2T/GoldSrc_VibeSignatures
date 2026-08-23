from __future__ import annotations

import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from analysis_config import validated_tag
from pull_request_route import parse_output_branch
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    normalized_relative_path,
    normalized_sha256,
    sha256_bytes,
)
from release_workflow_lib.manifest import GIT_SHA_PATTERN, parse_content_manifest_bytes

STAGE_SCHEMA_VERSION = 1
STATE_SEQUENCE = (
    "BUILDING",
    "HEAD_BOUND",
    "PR_CREATED",
    "READY",
    "PROMOTION_STARTED",
    "PROMOTED",
    "PROMOTION_COMPLETE",
)
DIAGNOSTIC_STATES = frozenset({"FAILED", "CANCELLED", "PR_CLOSED", "SUPERSEDED", "ABANDONED"})
MARKER_KEYS = {
    "schema_version",
    "state",
    "tag",
    "build_id",
    "content_manifest_sha256",
    "previous_state_sha256",
    "run_id",
    "run_attempt",
    "lease_owner",
    "bindings",
}
BINDING_KEYS = {
    "repository_id",
    "repository",
    "source_sha",
    "base_ref",
    "output_branch",
    "output_head_sha",
    "pr_number",
    "pr_head_sha",
    "pr_base_sha",
    "merge_sha",
    "promotion_run_id",
    "promotion_run_attempt",
    "promotion_workflow_repository",
    "promotion_workflow_path",
    "promotion_workflow_ref_sha",
    "tag_object_sha",
    "tag_target_sha",
    "release_id",
    "release_assets_sha256",
}
PR_INDEX_KEYS = {
    "schema_version",
    "repository_id",
    "repository",
    "base_ref",
    "tag",
    "build_id",
    "output_branch",
    "pr_number",
    "pr_head_sha",
    "pr_base_sha",
    "content_manifest_sha256",
}
BUILD_ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")


class ReleaseStageError(ReleaseWorkflowError):
    pass


def reject_release_path_links(path: str | Path, context: str) -> None:
    current = Path(path)
    for candidate in (current, *current.parents):
        if not candidate.exists() and not candidate.is_symlink():
            continue
        info = candidate.lstat()
        attributes = getattr(info, "st_file_attributes", 0)
        if candidate.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ReleaseStageError(f"{context} must not traverse a link/reparse point: {candidate}")


def validated_build_id(value: object) -> str:
    if not isinstance(value, str) or not BUILD_ID_RE.fullmatch(value):
        raise ReleaseStageError("build_id must be lowercase alphanumeric hyphen components")
    return value


def output_branch(tag: str, build_id: str) -> str:
    branch = f"gamesymbols/build/{validated_tag(tag)}/{validated_build_id(build_id)}"
    if parse_output_branch(branch) != (tag, build_id):
        raise ReleaseStageError("Output branch identity is not canonical")
    return branch


def _plain_directory(path: str | Path, context: str) -> Path:
    root = Path(path)
    reject_release_path_links(root, context)
    if not root.is_dir():
        raise ReleaseStageError(f"{context} must be a pre-provisioned directory")
    info = root.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    if root.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise ReleaseStageError(f"{context} must not be a link/reparse point")
    return root.resolve()


def release_staging_root(persisted_root: str | Path) -> Path:
    root = _plain_directory(persisted_root, "Persisted workspace")
    staging = root / "release-staging"
    staging.mkdir(exist_ok=True)
    return _plain_directory(staging, "Release staging root")


def build_stage_root(persisted_root: str | Path, tag: str, build_id: str) -> Path:
    path = release_staging_root(persisted_root) / validated_tag(tag) / validated_build_id(build_id)
    reject_release_path_links(path, "Release build stage")
    return path


@contextmanager
def release_tag_lock(persisted_root: str | Path, tag: str):
    staging = release_staging_root(persisted_root)
    lock_path = staging / "locks" / f"{validated_tag(tag)}.lock"
    reject_release_path_links(lock_path, "Release tag lock")
    lock_path.parent.mkdir(exist_ok=True)
    reject_release_path_links(lock_path.parent, "Release tag lock directory")
    handle = lock_path.open("a+b")
    if handle.seek(0, os.SEEK_END) == 0:
        handle.write(b"\0")
        handle.flush()
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _git_sha_or_none(value: object, context: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not GIT_SHA_PATTERN.fullmatch(value):
        raise ReleaseStageError(f"{context} must be a lowercase Git SHA-1 or null")
    return value


def _positive_int_or_none(value: object, context: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ReleaseStageError(f"{context} must be a positive integer or null")
    return value


def validate_bindings(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != BINDING_KEYS:
        raise ReleaseStageError("Stage bindings have unexpected or missing fields")
    repository_id = _positive_int_or_none(value["repository_id"], "repository_id")
    if repository_id is None:
        raise ReleaseStageError("repository_id is required")
    repository = value["repository"]
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseStageError("repository must be an owner/repository slug")
    source_sha = _git_sha_or_none(value["source_sha"], "source_sha")
    if source_sha is None:
        raise ReleaseStageError("source_sha is required")
    base_ref = value["base_ref"]
    if not isinstance(base_ref, str) or not base_ref or "/" in base_ref or "\\" in base_ref:
        raise ReleaseStageError("base_ref must be a simple branch name")
    branch = value["output_branch"]
    if not isinstance(branch, str):
        raise ReleaseStageError("output_branch is required")
    parse_output_branch(branch)
    for field in ("output_head_sha", "pr_head_sha", "pr_base_sha", "merge_sha"):
        _git_sha_or_none(value[field], field)
    for field in ("tag_object_sha", "tag_target_sha"):
        _git_sha_or_none(value[field], field)
    _positive_int_or_none(value["pr_number"], "pr_number")
    _positive_int_or_none(value["promotion_run_attempt"], "promotion_run_attempt")
    _positive_int_or_none(value["release_id"], "release_id")
    promotion_run_id = value["promotion_run_id"]
    if promotion_run_id is not None and (
        not isinstance(promotion_run_id, str) or not RUN_ID_RE.fullmatch(promotion_run_id)
    ):
        raise ReleaseStageError("promotion_run_id is invalid")
    promotion_workflow_repository = value["promotion_workflow_repository"]
    if promotion_workflow_repository is not None and (
        not isinstance(promotion_workflow_repository, str) or not REPOSITORY_RE.fullmatch(promotion_workflow_repository)
    ):
        raise ReleaseStageError("promotion_workflow_repository is invalid")
    promotion_workflow_path = value["promotion_workflow_path"]
    if promotion_workflow_path is not None:
        normalized_relative_path(promotion_workflow_path)
    _git_sha_or_none(value["promotion_workflow_ref_sha"], "promotion_workflow_ref_sha")
    release_assets_sha256 = value["release_assets_sha256"]
    if release_assets_sha256 is not None:
        normalized_sha256(release_assets_sha256, "release_assets_sha256")
    return dict(value)


def validate_pr_index(document: object, raw: bytes | None = None) -> dict:
    if not isinstance(document, dict) or set(document) != PR_INDEX_KEYS:
        raise ReleaseStageError("PR index has unexpected or missing fields")
    if document["schema_version"] != STAGE_SCHEMA_VERSION:
        raise ReleaseStageError("Unsupported PR index schema")
    tag = validated_tag(document["tag"])
    build_id = validated_build_id(document["build_id"])
    repository_id = _positive_int_or_none(document["repository_id"], "repository_id")
    if repository_id is None:
        raise ReleaseStageError("repository_id is required")
    repository = document["repository"]
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseStageError("repository must be an owner/repository slug")
    base_ref = document["base_ref"]
    if not isinstance(base_ref, str) or not base_ref or "/" in base_ref or "\\" in base_ref:
        raise ReleaseStageError("PR index base_ref must be a simple branch name")
    branch = document["output_branch"]
    if not isinstance(branch, str) or parse_output_branch(branch) != (tag, build_id):
        raise ReleaseStageError("PR index branch/tag/build identity mismatch")
    if _positive_int_or_none(document["pr_number"], "pr_number") is None:
        raise ReleaseStageError("pr_number is required")
    if _git_sha_or_none(document["pr_head_sha"], "pr_head_sha") is None:
        raise ReleaseStageError("pr_head_sha is required")
    if _git_sha_or_none(document["pr_base_sha"], "pr_base_sha") is None:
        raise ReleaseStageError("pr_base_sha is required")
    normalized_sha256(document["content_manifest_sha256"], "content_manifest_sha256")
    if raw is not None and canonical_json_bytes(document) != raw:
        raise ReleaseStageError("PR index is not canonical JSON")
    return dict(document)


def validate_marker(document: object, raw: bytes | None = None) -> dict:
    if not isinstance(document, dict) or set(document) != MARKER_KEYS:
        raise ReleaseStageError("Release stage marker has unexpected or missing fields")
    if document["schema_version"] != STAGE_SCHEMA_VERSION or document["state"] not in STATE_SEQUENCE:
        raise ReleaseStageError("Unsupported release stage marker schema/state")
    validated_tag(document["tag"])
    validated_build_id(document["build_id"])
    normalized_sha256(document["content_manifest_sha256"], "content_manifest_sha256")
    previous = document["previous_state_sha256"]
    if previous is not None:
        normalized_sha256(previous, "previous_state_sha256")
    if not isinstance(document["run_id"], str) or not RUN_ID_RE.fullmatch(document["run_id"]):
        raise ReleaseStageError("run_id is invalid")
    if _positive_int_or_none(document["run_attempt"], "run_attempt") is None:
        raise ReleaseStageError("run_attempt is required")
    if not isinstance(document["lease_owner"], str) or not RUN_ID_RE.fullmatch(document["lease_owner"]):
        raise ReleaseStageError("lease_owner is invalid")
    bindings = validate_bindings(document["bindings"])
    parsed = parse_output_branch(bindings["output_branch"])
    if parsed != (document["tag"], document["build_id"]):
        raise ReleaseStageError("Stage marker branch/tag/build identity mismatch")
    state_index = STATE_SEQUENCE.index(document["state"])
    required_by_state = {
        1: ("output_head_sha",),
        2: ("pr_number", "pr_head_sha", "pr_base_sha"),
        4: (
            "merge_sha",
            "promotion_run_id",
            "promotion_run_attempt",
            "promotion_workflow_repository",
            "promotion_workflow_path",
            "promotion_workflow_ref_sha",
        ),
        5: ("tag_object_sha", "tag_target_sha", "release_id", "release_assets_sha256"),
    }
    for minimum_index, fields in required_by_state.items():
        if state_index >= minimum_index and any(bindings[field] is None for field in fields):
            raise ReleaseStageError(f"Stage marker {document['state']} is missing required bindings")
        if state_index < minimum_index and any(bindings[field] is not None for field in fields):
            raise ReleaseStageError(f"Stage marker {document['state']} contains premature bindings")
    if raw is not None and canonical_json_bytes(document) != raw:
        raise ReleaseStageError("Release stage marker is not canonical JSON")
    return {**document, "bindings": bindings}


def _marker_path(stage_root: Path, state: str) -> Path:
    return stage_root / f"{state}.json"


def load_marker(stage_root: str | Path, state: str) -> tuple[dict, bytes]:
    path = _marker_path(Path(stage_root), state)
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseStageError(f"Unable to read release stage marker {path}: {exc}") from exc
    marker = validate_marker(document, raw)
    if marker["state"] != state:
        raise ReleaseStageError(f"Release marker filename/state mismatch: {path}")
    state_index = STATE_SEQUENCE.index(state)
    if state_index == 0:
        if marker["previous_state_sha256"] is not None:
            raise ReleaseStageError("BUILDING marker must not have a previous state")
    else:
        previous, previous_raw = load_marker(stage_root, STATE_SEQUENCE[state_index - 1])
        if marker["previous_state_sha256"] != sha256_bytes(previous_raw):
            raise ReleaseStageError(f"Release marker hash chain is broken at {state}")
        for field in ("tag", "build_id", "content_manifest_sha256", "run_id", "run_attempt", "lease_owner"):
            if marker[field] != previous[field]:
                raise ReleaseStageError(f"Release marker identity drift at {state}: {field}")
        for field, value in previous["bindings"].items():
            if value is not None and marker["bindings"][field] != value:
                raise ReleaseStageError(f"Release marker binding drift at {state}: {field}")
    return marker, raw


def _create_exact_file(path: Path, raw: bytes) -> None:
    reject_release_path_links(path, "Immutable stage file")
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_release_path_links(path.parent, "Immutable stage directory")
    if path.exists():
        if not path.is_file() or path.read_bytes() != raw:
            raise ReleaseStageError(f"Immutable stage file already exists with different bytes: {path}")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(raw)
    try:
        os.link(temporary, path)
    except FileExistsError:
        if path.read_bytes() != raw:
            raise ReleaseStageError(f"Concurrent immutable stage write differs: {path}")
    finally:
        if temporary.exists():
            temporary.unlink()


def _marker_document(
    *,
    state: str,
    tag: str,
    build_id: str,
    content_manifest_sha256: str,
    previous_state_sha256: str | None,
    run_id: str,
    run_attempt: int,
    lease_owner: str,
    bindings: dict,
) -> dict:
    return validate_marker(
        {
            "schema_version": STAGE_SCHEMA_VERSION,
            "state": state,
            "tag": tag,
            "build_id": build_id,
            "content_manifest_sha256": content_manifest_sha256,
            "previous_state_sha256": previous_state_sha256,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "lease_owner": lease_owner,
            "bindings": bindings,
        }
    )


def create_building_stage(
    *,
    persisted_root: str | Path,
    manifest_raw: bytes,
    build_id: str,
    repository_id: int,
    repository: str,
    base_ref: str,
    run_id: str,
    run_attempt: int,
    lease_owner: str,
) -> tuple[Path, dict]:
    manifest = parse_content_manifest_bytes(manifest_raw)
    tag = manifest["game_version"]
    stage_root = build_stage_root(persisted_root, tag, build_id)
    with release_tag_lock(persisted_root, tag):
        staging = release_staging_root(persisted_root)
        tag_root = staging / tag
        if tag_root.is_dir():
            for candidate in tag_root.iterdir():
                terminal = any((candidate / "diagnostics").glob("*-SUPERSEDED.json")) or any(
                    (candidate / "diagnostics").glob("*-ABANDONED.json")
                )
                if (
                    candidate != stage_root
                    and candidate.is_dir()
                    and _marker_path(candidate, "BUILDING").is_file()
                    and not terminal
                ):
                    raise ReleaseStageError(f"Another active release build already exists for {tag}: {candidate.name}")
        stage_root.mkdir(parents=True, exist_ok=True)
        reject_release_path_links(stage_root, "Release build stage")
        _create_exact_file(stage_root / "content-manifest.json", manifest_raw)
        bindings = {
            "repository_id": repository_id,
            "repository": repository,
            "source_sha": manifest["source_sha"],
            "base_ref": base_ref,
            "output_branch": output_branch(tag, build_id),
            "output_head_sha": None,
            "pr_number": None,
            "pr_head_sha": None,
            "pr_base_sha": None,
            "merge_sha": None,
            "promotion_run_id": None,
            "promotion_run_attempt": None,
            "promotion_workflow_repository": None,
            "promotion_workflow_path": None,
            "promotion_workflow_ref_sha": None,
            "tag_object_sha": None,
            "tag_target_sha": None,
            "release_id": None,
            "release_assets_sha256": None,
        }
        marker = _marker_document(
            state="BUILDING",
            tag=tag,
            build_id=build_id,
            content_manifest_sha256=sha256_bytes(manifest_raw),
            previous_state_sha256=None,
            run_id=run_id,
            run_attempt=run_attempt,
            lease_owner=lease_owner,
            bindings=bindings,
        )
        _create_exact_file(_marker_path(stage_root, "BUILDING"), canonical_json_bytes(marker))
        return stage_root, marker


def advance_stage(stage_root: str | Path, state: str, *, binding_updates: dict | None = None) -> dict:
    if state not in STATE_SEQUENCE[1:]:
        raise ReleaseStageError(f"Invalid stage transition target: {state}")
    target_index = STATE_SEQUENCE.index(state)
    previous_state = STATE_SEQUENCE[target_index - 1]
    root = Path(stage_root)
    previous, previous_raw = load_marker(root, previous_state)
    bindings = dict(previous["bindings"])
    for field, value in (binding_updates or {}).items():
        if field not in BINDING_KEYS:
            raise ReleaseStageError(f"Unknown stage binding update: {field}")
        bindings[field] = value
    marker = _marker_document(
        state=state,
        tag=previous["tag"],
        build_id=previous["build_id"],
        content_manifest_sha256=previous["content_manifest_sha256"],
        previous_state_sha256=sha256_bytes(previous_raw),
        run_id=previous["run_id"],
        run_attempt=previous["run_attempt"],
        lease_owner=previous["lease_owner"],
        bindings=bindings,
    )
    _create_exact_file(_marker_path(root, state), canonical_json_bytes(marker))
    return marker


def bind_pull_request(
    *,
    persisted_root: str | Path,
    tag: str,
    build_id: str,
    pr_number: int,
    pr_head_sha: str,
    pr_base_sha: str,
) -> dict:
    stage_root = build_stage_root(persisted_root, tag, build_id)
    head, _raw = load_marker(stage_root, "HEAD_BOUND")
    if head["bindings"]["output_head_sha"] != pr_head_sha:
        raise ReleaseStageError("Pull request head does not match HEAD_BOUND")
    created = advance_stage(
        stage_root,
        "PR_CREATED",
        binding_updates={"pr_number": pr_number, "pr_head_sha": pr_head_sha, "pr_base_sha": pr_base_sha},
    )
    index = {
        "schema_version": STAGE_SCHEMA_VERSION,
        "repository_id": created["bindings"]["repository_id"],
        "repository": created["bindings"]["repository"],
        "base_ref": created["bindings"]["base_ref"],
        "tag": tag,
        "build_id": build_id,
        "output_branch": created["bindings"]["output_branch"],
        "pr_number": pr_number,
        "pr_head_sha": pr_head_sha,
        "pr_base_sha": pr_base_sha,
        "content_manifest_sha256": created["content_manifest_sha256"],
    }
    index_path = release_staging_root(persisted_root) / "pr-index" / f"{pr_number}.json"
    _create_exact_file(index_path, canonical_json_bytes(index))
    return advance_stage(stage_root, "READY")


def load_pr_index(persisted_root: str | Path, pr_number: int) -> dict:
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number < 1:
        raise ReleaseStageError("pr_number must be positive")
    path = release_staging_root(persisted_root) / "pr-index" / f"{pr_number}.json"
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseStageError(f"Unable to read PR index {path}: {exc}") from exc
    return validate_pr_index(document, raw)


def repair_pr_index(
    *,
    persisted_root: str | Path,
    tag: str,
    build_id: str,
    pr_number: int,
    repository_id: int,
    repository: str,
    base_ref: str,
    output_branch_name: str,
    pr_head_sha: str,
    pr_base_sha: str,
    confirmation: str,
) -> Path:
    if confirmation != f"repair-index:{pr_number}:{tag}:{build_id}":
        raise ReleaseStageError("Repair-index confirmation does not match exact PR/tag/build identity")
    stage_root = build_stage_root(persisted_root, tag, build_id)
    if (stage_root / "READY.json").is_file():
        marker_state = "READY"
    elif (stage_root / "PR_CREATED.json").is_file():
        marker_state = "PR_CREATED"
    else:
        marker_state = "HEAD_BOUND"
    marker, _raw = load_marker(stage_root, marker_state)
    bindings = marker["bindings"]
    if bindings["pr_number"] is not None and bindings["pr_number"] != pr_number:
        raise ReleaseStageError("READY marker PR number mismatch")
    expected = {
        "repository_id": repository_id,
        "repository": repository,
        "base_ref": base_ref,
        "output_branch": output_branch_name,
        "pr_head_sha": pr_head_sha,
        "pr_base_sha": pr_base_sha,
    }
    for field, value in expected.items():
        if marker_state == "HEAD_BOUND" and field in {"pr_head_sha", "pr_base_sha"}:
            continue
        if bindings[field] != value:
            raise ReleaseStageError(f"PR index repair identity mismatch for {field}")
    if bindings["output_head_sha"] != pr_head_sha:
        raise ReleaseStageError("PR index repair head does not match HEAD_BOUND")
    if marker_state == "HEAD_BOUND":
        marker = advance_stage(
            stage_root,
            "PR_CREATED",
            binding_updates={"pr_number": pr_number, "pr_head_sha": pr_head_sha, "pr_base_sha": pr_base_sha},
        )
        bindings = marker["bindings"]
        marker_state = "PR_CREATED"
    index = {
        "schema_version": STAGE_SCHEMA_VERSION,
        "repository_id": bindings["repository_id"],
        "repository": bindings["repository"],
        "base_ref": bindings["base_ref"],
        "tag": tag,
        "build_id": build_id,
        "output_branch": bindings["output_branch"],
        "pr_number": pr_number,
        "pr_head_sha": bindings["pr_head_sha"],
        "pr_base_sha": bindings["pr_base_sha"],
        "content_manifest_sha256": marker["content_manifest_sha256"],
    }
    validate_pr_index(index)
    path = release_staging_root(persisted_root) / "pr-index" / f"{pr_number}.json"
    _create_exact_file(path, canonical_json_bytes(index))
    if marker_state == "PR_CREATED":
        advance_stage(stage_root, "READY")
    return path


def write_completion_record(stage_root: str | Path, document: dict) -> Path:
    root = Path(stage_root)
    promoted, _raw = load_marker(root, "PROMOTED")
    completion = {
        "schema_version": STAGE_SCHEMA_VERSION,
        "tag": promoted["tag"],
        "build_id": promoted["build_id"],
        "content_manifest_sha256": promoted["content_manifest_sha256"],
        "bindings": promoted["bindings"],
        "promotion": document,
    }
    staging = root.parents[1]
    path = staging / "completed" / promoted["tag"] / f"{promoted['build_id']}.json"
    _create_exact_file(path, canonical_json_bytes(completion))
    return path


def write_diagnostic(stage_root: str | Path, state: str, reason: str) -> Path:
    if state not in DIAGNOSTIC_STATES or not isinstance(reason, str) or not reason.strip():
        raise ReleaseStageError("Invalid diagnostic state/reason")
    root = Path(stage_root)
    diagnostics = root / "diagnostics"
    reject_release_path_links(diagnostics, "Release diagnostic directory")
    diagnostics.mkdir(exist_ok=True)
    reject_release_path_links(diagnostics, "Release diagnostic directory")
    sequence = len(tuple(diagnostics.glob("*.json"))) + 1
    document = {"schema_version": 1, "state": state, "reason": reason.strip()}
    path = diagnostics / f"{sequence:04d}-{state}.json"
    _create_exact_file(path, canonical_json_bytes(document))
    return path
