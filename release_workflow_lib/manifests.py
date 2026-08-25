"""Multi-gamever release manifest contract.

GoldSrc publishes all game versions under a single date-versioned release
(``vYYYYMMDD[a-z]``). The tracked release manifest at
``release-manifests/<version>.json`` binds that version to the immutable source
commit and one per-gamever provenance record, so a generated-output PR can be
verified by recomputing tracked hashes from exact Git blobs.
"""

from __future__ import annotations

import re
from pathlib import Path

from gamedata_contract import discover_generator_modules, generator_contract_sha256
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    SHA256_PATTERN,
    canonical_json_bytes,
    inventory_sha256,
    load_json_object,
    sha256_file,
    tracked_output_inventory,
    write_canonical_json,
)

GAMEVER_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+$")
VERSION_RE = re.compile(r"^v[0-9]{8}[a-z]?\Z")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
BUILD_ID_RE = re.compile(r"^[0-9]+-[0-9]+$")
BRANCH_RE = re.compile(r"^gamesymbols/build/(?P<version>v[0-9]{8}[a-z]?)\Z")
ALLOWED_REPOSITORIES = {"HLND2T/GoldSrc_VibeSignatures", "hzqst/GoldSrc_VibeSignatures"}
SCHEMA_VERSION = 1

GAMEVER_ENTRY_FIELDS = {
    "gamever",
    "candidate_sha256",
    "analysis_config_path",
    "analysis_config_sha256",
    "gamedata_path",
    "gamedata_manifest_sha256",
    "gamedata_inventory_sha256",
    "generator_contract_sha256",
}
TRACKED_FIELDS = {
    "schema_version",
    "version",
    "mode",
    "build_id",
    "source_sha",
    "workflow_run_url",
    "bin_manifest_sha256",
    "tracked_output_manifest_sha256",
    "gamevers",
}


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


def require_mode(value: object) -> str:
    if value not in {"new", "republish"}:
        raise ReleaseWorkflowError(f"invalid release mode: {value!r}")
    return value


def require_build_id(value: object) -> str:
    if not isinstance(value, str) or not BUILD_ID_RE.fullmatch(value):
        raise ReleaseWorkflowError(f"invalid BUILD_ID: {value!r}")
    return value


def format_output_branch(version: str) -> str:
    return f"gamesymbols/build/{require_version(version)}"


def parse_output_branch(branch: str) -> str:
    if not isinstance(branch, str):
        raise ReleaseWorkflowError("generated-output branch must be a string")
    match = BRANCH_RE.fullmatch(branch)
    if not match:
        raise ReleaseWorkflowError(f"invalid generated-output branch: {branch!r}")
    return match.group("version")


def build_gamever_entry(
    *,
    gamever: str,
    candidate_sha256: str,
    analysis_config_path: str,
    analysis_config_sha256: str,
    gamedata_path: str,
    gamedata_manifest_sha256: str,
    gamedata_inventory_sha256: str,
    generator_contract_sha256: str,
) -> dict:
    gamever = require_gamever(gamever)
    require_sha256(candidate_sha256, "candidate_sha256")
    require_sha256(analysis_config_sha256, "analysis_config_sha256")
    require_sha256(gamedata_manifest_sha256, "gamedata_manifest_sha256")
    require_sha256(gamedata_inventory_sha256, "gamedata_inventory_sha256")
    require_sha256(generator_contract_sha256, "generator_contract_sha256")
    if analysis_config_path != f"configs/{gamever}.yaml":
        raise ReleaseWorkflowError("analysis_config_path must be the canonical versioned path")
    if gamedata_path != f"gamedata/{gamever}":
        raise ReleaseWorkflowError("gamedata_path must be the canonical versioned path")
    return {
        "gamever": gamever,
        "candidate_sha256": candidate_sha256,
        "analysis_config_path": analysis_config_path,
        "analysis_config_sha256": analysis_config_sha256,
        "gamedata_path": gamedata_path,
        "gamedata_manifest_sha256": gamedata_manifest_sha256,
        "gamedata_inventory_sha256": gamedata_inventory_sha256,
        "generator_contract_sha256": generator_contract_sha256,
    }


def build_tracked_manifest(
    *,
    version: str,
    mode: str,
    build_id: str,
    source_sha: str,
    workflow_run_url: str,
    bin_manifest_sha256: str,
    tracked_output_manifest_sha256: str,
    gamevers: list[dict],
) -> dict:
    version = require_version(version)
    require_mode(mode)
    build_id = require_build_id(build_id)
    source_sha = require_sha(source_sha, "SOURCE_SHA")
    require_sha256(bin_manifest_sha256, "bin_manifest_sha256")
    require_sha256(tracked_output_manifest_sha256, "tracked_output_manifest_sha256")
    if not workflow_run_url.startswith("https://github.com/"):
        raise ReleaseWorkflowError("workflow_run_url must be a GitHub Actions URL")
    if not isinstance(gamevers, list) or not gamevers:
        raise ReleaseWorkflowError("release manifest must bind at least one gamever")
    entries = [build_gamever_entry(**entry) for entry in gamevers]
    seen = {entry["gamever"] for entry in entries}
    if len(seen) != len(entries):
        raise ReleaseWorkflowError("release manifest has duplicate gamever entries")
    return {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "mode": mode,
        "build_id": build_id,
        "source_sha": source_sha,
        "workflow_run_url": workflow_run_url,
        "bin_manifest_sha256": bin_manifest_sha256,
        "tracked_output_manifest_sha256": tracked_output_manifest_sha256,
        "gamevers": entries,
    }


def validate_tracked_manifest(manifest: dict) -> dict:
    if set(manifest) != TRACKED_FIELDS or manifest.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseWorkflowError("tracked release manifest has unexpected or missing fields")
    expected = build_tracked_manifest(
        version=manifest["version"],
        mode=manifest["mode"],
        build_id=manifest["build_id"],
        source_sha=manifest["source_sha"],
        workflow_run_url=manifest["workflow_run_url"],
        bin_manifest_sha256=manifest["bin_manifest_sha256"],
        tracked_output_manifest_sha256=manifest["tracked_output_manifest_sha256"],
        gamevers=manifest["gamevers"],
    )
    if manifest != expected:
        raise ReleaseWorkflowError("tracked release manifest is not canonical")
    return manifest


def load_tracked_manifest(path: Path) -> dict:
    manifest = validate_tracked_manifest(load_json_object(path))
    if Path(path).read_bytes() != canonical_json_bytes(manifest):
        raise ReleaseWorkflowError(f"tracked release manifest is not canonically encoded: {path}")
    return manifest


def verify_tracked_outputs(repo_root: Path, manifest: dict) -> list[dict]:
    gamevers = [entry["gamever"] for entry in manifest["gamevers"]]
    inventory = tracked_output_inventory(repo_root, gamevers)
    if inventory_sha256(inventory) != manifest["tracked_output_manifest_sha256"]:
        raise ReleaseWorkflowError("tracked output manifest hash mismatch")
    try:
        modules = discover_generator_modules(Path(repo_root) / "gamedata-generators")
    except ValueError as exc:
        raise ReleaseWorkflowError(f"trusted generator contract is invalid: {exc}") from exc
    generator_digest = generator_contract_sha256(modules)
    for entry in manifest["gamevers"]:
        gamever = entry["gamever"]
        snapshot = next(item for item in inventory if item["path"] == f"gamesymbols/{gamever}.yaml")
        if snapshot["sha256"] != entry["candidate_sha256"]:
            raise ReleaseWorkflowError(f"published snapshot does not match candidate hash for {gamever}")
        gamedata_inventory = [item for item in inventory if item["path"].startswith(f"gamedata/{gamever}/")]
        if inventory_sha256(gamedata_inventory) != entry["gamedata_inventory_sha256"]:
            raise ReleaseWorkflowError(f"versioned gamedata manifest hash mismatch for {gamever}")
        if generator_digest != entry["generator_contract_sha256"]:
            raise ReleaseWorkflowError(f"generator contract hash mismatch for {gamever}")
    return inventory


def write_release_metadata(
    *,
    output_dir: Path,
    manifest: dict,
    output_merge_sha: str,
    tag_sha: str,
    repository: str,
    assets: list[Path],
) -> tuple[Path, Path, Path]:
    version = manifest["version"]
    output_merge_sha = require_sha(output_merge_sha, "OUTPUT_MERGE_SHA")
    tag_sha = require_sha(tag_sha, "tag SHA")
    if repository not in ALLOWED_REPOSITORIES:
        raise ReleaseWorkflowError(f"repository is not allowlisted: {repository}")
    asset_records = [
        {"name": path.name, "size": path.stat().st_size, "sha256": sha256_file(path)} for path in sorted(assets)
    ]
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "mode": manifest["mode"],
        "build_id": manifest["build_id"],
        "tag_sha": tag_sha,
        "source_sha": manifest["source_sha"],
        "output_merge_sha": output_merge_sha,
        "bin_manifest_sha256": manifest["bin_manifest_sha256"],
        "tracked_output_manifest_sha256": manifest["tracked_output_manifest_sha256"],
        "gamevers": manifest["gamevers"],
        "assets": asset_records,
    }
    output_dir = Path(output_dir)
    provenance_path = output_dir / f"release-provenance-{version}.json"
    write_canonical_json(provenance_path, provenance)
    checksum_path = output_dir / f"SHA256SUMS-{version}.txt"
    checksum_assets = [*assets, provenance_path]
    checksum_path.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in sorted(checksum_assets)),
        encoding="utf-8",
    )
    release_url = f"https://github.com/{repository}/releases/download/{version}"
    commit_url = f"https://github.com/{repository}/commit"
    notes_lines = [
        f"## GoldSrc game symbols {version}",
        "",
        "Validated release artifacts generated from the accepted repository output.",
        "",
        f"- Build mode: `{manifest['mode']}`",
        f"- Build ID: `{manifest['build_id']}`",
        f"- Source commit: [`{manifest['source_sha'][:7]}`]({commit_url}/{manifest['source_sha']})",
        f"- Output merge: [`{output_merge_sha[:7]}`]({commit_url}/{output_merge_sha})",
        f"- Tag target: [`{tag_sha[:7]}`]({commit_url}/{tag_sha})",
        "",
        "### Downloads",
        "",
    ]
    for asset in asset_records:
        notes_lines.append(f"- [`{asset['name']}`]({release_url}/{asset['name']})")
    notes_lines.extend(
        [
            f"- [`{checksum_path.name}`]({release_url}/{checksum_path.name}) — SHA-256 checksums",
            f"- [`{provenance_path.name}`]({release_url}/{provenance_path.name}) — machine-readable build provenance",
            "",
        ]
    )
    notes_path = output_dir / f"release-notes-{version}.md"
    notes_path.write_text("\n".join(notes_lines), encoding="utf-8")
    return provenance_path, checksum_path, notes_path
