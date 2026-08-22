"""Validated root-level registry for broad game-symbol impact rules."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml

from analysis_config import validated_tag
from analysis_planner import PLATFORMS, SYMBOL_CATEGORIES

REGISTRY_SCHEMA_VERSION = 1
SCOPES = frozenset({"all", "platform", "category", "skill"})


class ImpactRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class ImpactRule:
    paths: tuple[str, ...]
    scope: str
    platforms: frozenset[str]
    categories: frozenset[str]
    skills: frozenset[str]
    tags: frozenset[str] | None
    reason: str

    def matches_path(self, path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in self.paths)


def _strings(value: object, field: str, *, required: bool = False) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ImpactRegistryError(f"{field} must be a non-empty list of strings")
    return tuple(item.strip() for item in value)


def _validate_pattern(value: str, field: str) -> str:
    if (
        not value
        or "\\" in value
        or PurePosixPath(value).is_absolute()
        or PureWindowsPath(value).is_absolute()
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
        or any(marker in value for marker in ("[", "]", "{", "}"))
    ):
        raise ImpactRegistryError(f"{field} must be a safe repo-relative POSIX path or limited glob")
    return value


def parse_impact_registry(document: object) -> tuple[ImpactRule, ...]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "rules"}:
        raise ImpactRegistryError("Impact registry must contain only schema_version and rules")
    if document["schema_version"] != REGISTRY_SCHEMA_VERSION:
        raise ImpactRegistryError(f"Unsupported impact registry schema: {document['schema_version']!r}")
    if not isinstance(document["rules"], list):
        raise ImpactRegistryError("Impact registry rules must be a list")

    rules = []
    for index, raw in enumerate(document["rules"]):
        context = f"rules[{index}]"
        if not isinstance(raw, dict):
            raise ImpactRegistryError(f"{context} must be a mapping")
        unknown = set(raw) - {"paths", "scope", "platforms", "categories", "skills", "tags", "reason"}
        if unknown:
            raise ImpactRegistryError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
        paths = tuple(
            _validate_pattern(value, f"{context}.paths")
            for value in _strings(raw.get("paths"), f"{context}.paths", required=True)
        )
        scope = raw.get("scope")
        if scope not in SCOPES:
            raise ImpactRegistryError(f"{context}.scope must be one of: {', '.join(sorted(SCOPES))}")
        platforms = frozenset(_strings(raw.get("platforms"), f"{context}.platforms"))
        categories = frozenset(_strings(raw.get("categories"), f"{context}.categories"))
        skills = frozenset(_strings(raw.get("skills"), f"{context}.skills"))
        tags_raw = _strings(raw.get("tags"), f"{context}.tags")
        tags = frozenset(validated_tag(tag) for tag in tags_raw) if tags_raw else None
        if platforms - set(PLATFORMS):
            raise ImpactRegistryError(f"{context}.platforms contains an unknown platform")
        if categories - SYMBOL_CATEGORIES:
            raise ImpactRegistryError(f"{context}.categories contains an unknown category")
        if scope == "platform" and not platforms:
            raise ImpactRegistryError(f"{context}.platform scope requires platforms")
        if scope == "category" and not categories:
            raise ImpactRegistryError(f"{context}.category scope requires categories")
        if scope == "skill" and not skills:
            raise ImpactRegistryError(f"{context}.skill scope requires skills")
        if scope != "platform" and platforms or scope != "category" and categories or scope != "skill" and skills:
            raise ImpactRegistryError(f"{context} has selectors that do not match scope {scope!r}")
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ImpactRegistryError(f"{context}.reason must be non-empty text")
        rules.append(ImpactRule(paths, scope, platforms, categories, skills, tags, reason.strip()))
    return tuple(rules)


def load_impact_registry(path: str | Path) -> tuple[ImpactRule, ...]:
    try:
        document = yaml.safe_load(Path(path).read_bytes())
    except (OSError, yaml.YAMLError) as exc:
        raise ImpactRegistryError(f"Unable to read impact registry {path}: {exc}") from exc
    return parse_impact_registry(document)
