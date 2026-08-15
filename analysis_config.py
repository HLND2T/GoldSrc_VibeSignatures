"""Resolve safe tag-named analysis configs from the repository."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

TAG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+$", re.ASCII)
REPO_ROOT = Path(__file__).resolve().parent


class AnalysisConfigError(RuntimeError):
    pass


def validated_tag(tag: str) -> str:
    value = str(tag)
    if not TAG_RE.fullmatch(value):
        raise AnalysisConfigError(
            f"Invalid tag {tag!r}; expected lowercase game and numeric version segments separated by hyphens"
        )
    return value


def analysis_config_repo_path(tag: str) -> str:
    return f"configs/{validated_tag(tag)}.yaml"


def default_analysis_config_path(tag: str, *, repo_root: Path | None = None) -> Path:
    root = Path(repo_root or REPO_ROOT).resolve()
    path = (root / analysis_config_repo_path(tag)).resolve()
    if path.parent != (root / "configs").resolve():
        raise AnalysisConfigError(f"Analysis config escapes configs directory: {path}")
    return path


def resolve_analysis_config(
    tag: str, explicit_path: str | Path | None = None, *, repo_root: Path | None = None
) -> Path:
    validated_tag(tag)
    path = (
        default_analysis_config_path(tag, repo_root=repo_root)
        if explicit_path is None
        else Path(explicit_path).resolve()
    )
    if not path.is_file():
        raise AnalysisConfigError(f"Analysis config file not found: {path}")
    return path


def iter_analysis_config_tags(repo_root: Path | None = None) -> list[str]:
    """Return every declared analysis tag, ordered for deterministic batch runs.

    ``configs/config.yaml`` is the single authority for ``-allgamever`` batches
    when present: its ``gamevers`` list fixes both membership and order, so a
    tag only runs when it is explicitly declared. A declared tag whose per-game
    config is missing is a configuration error and raises rather than being
    silently dropped.

    Without ``configs/config.yaml``, the legacy order is used so older checkouts
    keep working: the ``download.yaml`` manifest declaration order first (the same
    "release order" that ``download_depot.py -all`` uses), then tags with a config
    file but no manifest entry appended in lexical order so they are never dropped.
    """
    root = Path(repo_root or REPO_ROOT).resolve()
    configs_dir = (root / "configs").resolve()
    index_path = configs_dir / "config.yaml"
    if index_path.is_file():
        try:
            document = yaml.safe_load(index_path.read_bytes()) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise AnalysisConfigError(f"Unable to read {index_path}: {exc}") from exc
        gamevers = document.get("gamevers") if isinstance(document, dict) else None
        if not isinstance(gamevers, list):
            raise AnalysisConfigError(f"{index_path} must declare a 'gamevers' list")
        tags: list[str] = []
        seen: set[str] = set()
        for value in gamevers:
            tag = str(value or "").strip()
            if not tag:
                raise AnalysisConfigError(f"{index_path} contains an empty gamever entry")
            if tag in seen:
                raise AnalysisConfigError(f"{index_path} declares duplicate gamever {tag!r}")
            seen.add(tag)
            validated_tag(tag)
            if not (configs_dir / f"{tag}.yaml").is_file():
                raise AnalysisConfigError(f"{index_path} declares {tag!r} but {configs_dir / f'{tag}.yaml'} is missing")
            tags.append(tag)
        return tags

    seen = set()
    manifest_order: list[str] = []
    try:
        manifest_path = root / "download.yaml"
        document = yaml.safe_load(manifest_path.read_bytes()) or {} if manifest_path.is_file() else {}
    except (OSError, yaml.YAMLError):
        document = {}
    downloads = document.get("downloads") if isinstance(document, dict) else None
    if isinstance(downloads, list):
        for entry in downloads:
            if not isinstance(entry, dict):
                continue
            tag = str(entry.get("tag", "")).strip()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            manifest_order.append(tag)

    tags = []
    for tag in manifest_order:
        if (configs_dir / f"{tag}.yaml").is_file():
            tags.append(validated_tag(tag))
    for path in sorted(configs_dir.glob("*.yaml")):
        tag = path.stem
        if tag not in seen:
            tags.append(validated_tag(tag))
    return tags


def analysis_config_sha256(path: str | Path) -> str:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise AnalysisConfigError(f"Analysis config file not found: {resolved}")
    return hashlib.sha256(resolved.read_bytes()).hexdigest()
