from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

from analysis_config import validated_tag
from release_workflow_lib.errors import ContentManifestError
from release_workflow_lib.hashing import canonical_json_bytes, normalized_relative_path, normalized_sha256

CONTENT_MANIFEST_SCHEMA_VERSION = 1
CONTENT_MANIFEST_KEYS = {
    "schema_version",
    "game_version",
    "release_tag",
    "repository_id",
    "source_sha",
    "bin_gitlink_sha",
    "candidate_sha256",
    "snapshot_schema_version",
    "analysis_output_contract_version",
    "metadata_sha256",
    "tracked_content_inventory_sha256",
    "snapshot_binary_inventory_sha256",
    "analysis_config_path",
    "analysis_config_sha256",
    "config_digest_version",
    "config_contract_sha256",
    "gamedata_path",
    "gamedata_manifest_sha256",
    "generator_contract_sha256",
    "workflow_repository",
    "workflow_path",
    "workflow_ref_sha",
    "release_tool_contract_sha256",
}
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _positive_int(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ContentManifestError(f"{context} must be a positive integer")
    return value


def _git_sha(value: object, context: str) -> str:
    if not isinstance(value, str) or not GIT_SHA_PATTERN.fullmatch(value):
        raise ContentManifestError(f"{context} must be a lowercase Git SHA-1")
    return value


def validate_content_manifest(document: Mapping) -> dict:
    if not isinstance(document, dict) or set(document) != CONTENT_MANIFEST_KEYS:
        raise ContentManifestError("Release content manifest has unexpected or missing fields")
    if document["schema_version"] != CONTENT_MANIFEST_SCHEMA_VERSION:
        raise ContentManifestError("Unsupported release content manifest schema")
    try:
        game_version = validated_tag(document["game_version"])
        release_tag = validated_tag(document["release_tag"])
    except (TypeError, ValueError) as exc:
        raise ContentManifestError(f"Release manifest tag is invalid: {exc}") from exc
    if release_tag != game_version:
        raise ContentManifestError("Initial release_tag contract requires the exact game_version")
    _positive_int(document["repository_id"], "repository_id")
    for field in ("source_sha", "bin_gitlink_sha", "workflow_ref_sha"):
        _git_sha(document[field], field)
    for field in (
        "candidate_sha256",
        "metadata_sha256",
        "tracked_content_inventory_sha256",
        "snapshot_binary_inventory_sha256",
        "analysis_config_sha256",
        "config_contract_sha256",
        "gamedata_manifest_sha256",
        "generator_contract_sha256",
        "release_tool_contract_sha256",
    ):
        try:
            normalized_sha256(document[field], field)
        except ValueError as exc:
            raise ContentManifestError(str(exc)) from exc
    for field in ("snapshot_schema_version", "analysis_output_contract_version", "config_digest_version"):
        _positive_int(document[field], field)
    for field in ("analysis_config_path", "gamedata_path", "workflow_path"):
        try:
            normalized = normalized_relative_path(document[field])
        except ValueError as exc:
            raise ContentManifestError(str(exc)) from exc
        if normalized != document[field]:
            raise ContentManifestError(f"{field} is not canonical")
    workflow_repository = document["workflow_repository"]
    if not isinstance(workflow_repository, str) or not REPOSITORY_PATTERN.fullmatch(workflow_repository):
        raise ContentManifestError("workflow_repository must be an owner/repository slug")
    return dict(document)


def parse_content_manifest_bytes(data: bytes) -> dict:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContentManifestError(f"Unable to parse release content manifest: {exc}") from exc
    validated = validate_content_manifest(document)
    if canonical_json_bytes(validated) != data:
        raise ContentManifestError("Release content manifest is not canonical JSON")
    return validated


def load_content_manifest(path: str | Path) -> tuple[dict, bytes]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ContentManifestError(f"Unable to read release content manifest {path}: {exc}") from exc
    return parse_content_manifest_bytes(raw), raw
