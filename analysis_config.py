"""Resolve safe tag-named analysis configs from the repository."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

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


def analysis_config_sha256(path: str | Path) -> str:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise AnalysisConfigError(f"Analysis config file not found: {resolved}")
    return hashlib.sha256(resolved.read_bytes()).hexdigest()
