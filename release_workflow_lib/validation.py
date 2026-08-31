"""Release build input validation, old-version baseline selection, and republish invalidation."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.analysis_sources import build_source_index
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.operations import restore_snapshot
from gamesymbol_snapshot_lib.paths import ensure_real_tree, path_from_key
from gamesymbol_snapshot_lib.pr_cli import GitRepository
from gamesymbol_snapshot_lib.pr_validation import build_invalidation_plan
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    GAMEVER_RE,
    load_tracked_manifest,
    require_gamever,
    require_mode,
    require_sha,
    require_version,
)


def git_output(arguments: list[str], *, text: bool = True):
    result = subprocess.run(["git", *arguments], capture_output=True, text=text, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() if text else result.stderr.decode(errors="replace").strip()
        raise ReleaseWorkflowError(stderr or f"git {' '.join(arguments)} failed")
    return result.stdout.strip() if text else result.stdout


def validate_build_input(*, repository: str, version: str, source_sha: str, mode: str, default_ref: str) -> None:
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    version = require_version(version)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    require_mode(mode)
    git_output(["cat-file", "-e", f"{source_sha}^{{commit}}"])
    result = subprocess.run(["git", "merge-base", "--is-ancestor", source_sha, default_ref], check=False)
    if result.returncode != 0:
        raise ReleaseWorkflowError(f"SOURCE_SHA is not reachable from {default_ref}: {source_sha}")
    raw = git_output(["show", f"{source_sha}:configs/config.yaml"], text=False)
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ReleaseWorkflowError("configs/config.yaml at SOURCE_SHA is invalid") from exc
    gamevers = document.get("gamevers") if isinstance(document, dict) else None
    if not isinstance(gamevers, list) or not gamevers:
        raise ReleaseWorkflowError("configs/config.yaml at SOURCE_SHA must declare a non-empty gamevers list")
    for tag in gamevers:
        require_gamever(str(tag))
    tag_exists = (
        subprocess.run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{version}"], check=False).returncode == 0
    )
    if mode == "new" and tag_exists:
        raise ReleaseWorkflowError(f"mode=new requires tag {version} to be absent")
    if mode == "republish" and not tag_exists:
        raise ReleaseWorkflowError(f"mode=republish requires tag {version} to exist")


def _gamever_key(gamever: str) -> tuple[str, int]:
    if not GAMEVER_RE.fullmatch(str(gamever)):
        raise ReleaseWorkflowError(f"invalid GAMEVER: {gamever!r}")
    family, buildnum = gamever.rsplit("-", 1)
    return family, int(buildnum)


def prepare_oldgamever_baseline(
    *, repo_root: str | Path, gamever: str, bindir: str | Path, artifactdir: str | Path
) -> dict:
    """Select the highest older same-family snapshot as an analysis baseline."""
    repo_root = Path(repo_root).resolve()
    gamever = require_gamever(gamever)
    bindir = Path(bindir)
    if not bindir.is_absolute():
        bindir = repo_root / bindir
    artifactdir = Path(artifactdir)
    if not artifactdir.is_absolute():
        artifactdir = repo_root / artifactdir

    current = _gamever_key(gamever)
    snapshot_root = repo_root / "gamesymbols"
    candidates = []
    if snapshot_root.is_dir():
        for snapshot in snapshot_root.glob("*.yaml"):
            candidate = snapshot.stem
            if GAMEVER_RE.fullmatch(candidate) and _gamever_key(candidate)[0] == current[0]:
                if _gamever_key(candidate) < current:
                    candidates.append((candidate, snapshot))
    if not candidates:
        raise ReleaseWorkflowError(f"no trusted old-version snapshot is available for {gamever}")

    oldgamever, snapshot = max(candidates, key=lambda item: _gamever_key(item[0]))
    config = repo_root / "configs" / f"{oldgamever}.yaml"
    if not config.is_file():
        raise ReleaseWorkflowError(f"old-version analysis config is missing: {config}")
    try:
        restore_snapshot(
            oldgamever,
            str(bindir),
            str(config),
            str(snapshot),
            artifactdir=str(artifactdir),
            replace=True,
        )
    except (SnapshotError, OSError, UnicodeError) as exc:
        raise ReleaseWorkflowError(f"unable to restore trusted snapshot for {oldgamever}: {exc}") from exc
    return {
        "oldgamever": oldgamever,
        "snapshot": str(snapshot),
        "config": str(config),
    }


def _source_tree(repo: GitRepository, ref: str) -> dict[str, bytes]:
    paths = [
        path
        for path in repo.list_files(ref)
        if path == "ida_analyze_util.py" or path.startswith("ida_preprocessor_scripts/")
    ]
    return {path: value for path in paths if (value := repo.read(ref, path)) is not None}


def invalidate_republish(
    *,
    repo_root: Path,
    gamever: str,
    version: str,
    source_sha: str,
    bindir: Path,
    artifactdir: Path,
) -> int:
    """Invalidate affected analysis outputs so a republish re-analyzes only what changed."""
    repo_root = Path(repo_root).resolve()
    gamever = require_gamever(gamever)
    version = require_version(version)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    bindir = Path(bindir)
    if not bindir.is_absolute():
        bindir = repo_root / bindir
    artifactdir = Path(artifactdir)
    if not artifactdir.is_absolute():
        artifactdir = repo_root / artifactdir

    manifest = load_tracked_manifest(repo_root / "release-manifests" / f"{version}.json")
    entry = next((item for item in manifest["gamevers"] if item["gamever"] == gamever), None)
    if entry is None:
        raise ReleaseWorkflowError(f"release manifest has no entry for {gamever}")
    base_sha = require_sha(manifest["source_sha"], "previous SOURCE_SHA")
    if base_sha == source_sha:
        raise ReleaseWorkflowError("republish SOURCE_SHA must be newer than the accepted generator source")

    repo = GitRepository(repo_root)
    result = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", base_sha, source_sha], check=False
    )
    if result.returncode != 0:
        raise ReleaseWorkflowError("previous accepted SOURCE_SHA is not an ancestor of the rebuild SOURCE_SHA")

    changes = repo.changed_paths(base_sha, source_sha)
    head_contract = load_contract(repo_root / "configs" / f"{gamever}.yaml", gamever, bindir, artifactdir=artifactdir)
    base_config_raw = repo.read(base_sha, f"configs/{gamever}.yaml")
    if base_config_raw is None:
        raise ReleaseWorkflowError(f"base analysis config is missing for {gamever} at {base_sha}")
    with tempfile.TemporaryDirectory(prefix="release-base-") as temporary:
        base_config = Path(temporary) / f"{gamever}.yaml"
        base_config.write_bytes(base_config_raw)
        base_contract = load_contract(base_config, gamever, bindir, artifactdir=artifactdir)
        plan = build_invalidation_plan(
            base_contract,
            head_contract,
            None,
            None,
            changes,
            repo_root,
            base_sources=build_source_index(base_contract, _source_tree(repo, base_sha)),
            head_sources=build_source_index(head_contract, _source_tree(repo, source_sha)),
        )

    game_root = artifactdir / gamever
    ensure_real_tree(artifactdir, game_root)
    deleted = 0
    for key in sorted(plan.paths):
        target = path_from_key(game_root, key)
        if target.is_file():
            target.unlink()
            deleted += 1
    for reason in plan.reasons:
        print(reason)
    print(f"Invalidated {len(plan.paths)} affected output(s); deleted {deleted} YAML file(s)")
    return deleted
