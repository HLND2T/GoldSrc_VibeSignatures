"""Canonical release and game-version identifier validation."""

from __future__ import annotations

import re

from analysis_config import TAG_RE as GAMEVER_RE
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import SHA256_PATTERN

VERSION_RE = re.compile(r"^v[0-9]{8}[a-z]?\Z")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def require_gamever(value: object) -> str:
    if not isinstance(value, str) or not GAMEVER_RE.fullmatch(value):
        raise ReleaseWorkflowError(f"invalid GAMEVER: {value!r}")
    return value


def require_version(value: object) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise ReleaseWorkflowError(f"invalid release version: {value!r}")
    return value


def require_sha(value: object, label: str = "SHA") -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise ReleaseWorkflowError(f"{label} must be a full 40-hex commit SHA")
    return value.lower()


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ReleaseWorkflowError(f"{label} must be a lowercase 64-hex SHA-256 digest")
    return value
