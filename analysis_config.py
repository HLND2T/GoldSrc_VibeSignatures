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

    The order follows the download manifest declaration order (``download.yaml``)
    when present, so ``-allgamever`` batches in the same "release order" that
    ``download_depot.py -all`` uses. Tags with a config file but no manifest entry
    are appended in lexical order so they are never silently dropped.
    """
    root = Path(repo_root or REPO_ROOT).resolve()
    configs_dir = (root / "configs").resolve()
    seen: set[str] = set()
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

    tags: list[str] = []
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
