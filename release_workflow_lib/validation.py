"""Release build input validation and old-version baseline selection."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from analysis_config import validated_tag
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.operations import restore_snapshot
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.manifests import (
    ALLOWED_REPOSITORIES,
    GAMEVER_RE,
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


def _gamever_key(gamever: str) -> tuple[str, int]:
    if not GAMEVER_RE.fullmatch(str(gamever)):
        raise ReleaseWorkflowError(f"invalid GAMEVER: {gamever!r}")
    family, buildnum = gamever.rsplit("-", 1)
    return family, int(buildnum)


def prepare_oldgamever_baseline(*, repo_root: str | Path, gamever: str, bindir: str | Path) -> dict:
    """Select the highest older same-family snapshot as an analysis baseline."""
    repo_root = Path(repo_root).resolve()
    gamever = require_gamever(gamever)
    bindir = Path(bindir)
    if not bindir.is_absolute():
        bindir = repo_root / bindir

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
        restore_snapshot(oldgamever, str(bindir), str(config), str(snapshot), replace=True)
    except (SnapshotError, OSError, UnicodeError) as exc:
        raise ReleaseWorkflowError(f"unable to restore trusted snapshot for {oldgamever}: {exc}") from exc
    return {
        "oldgamever": oldgamever,
        "snapshot": str(snapshot),
        "config": str(config),
    }


def invalidate_republish(*, repo_root: Path, gamever: str, source_sha: str, bindir: Path) -> int:
    raise ReleaseWorkflowError("republish mode is not supported yet")
