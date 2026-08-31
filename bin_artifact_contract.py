"""Formal repository contract for tracked per-symbol analysis artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from gamesymbol_snapshot_lib.codec import canonical_yaml_bytes
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.operations import collect_actual_files
from gamesymbol_snapshot_lib.paths import canonical_key, ensure_real_tree, is_reparse_point

INVENTORY_SCHEMA_VERSION = 1
INVENTORY_DOMAIN_SEPARATOR = b"bin-artifact-inventory:v1\n"


class BinArtifactContractError(ValueError):
    pass


@dataclass(frozen=True)
class ArtifactInventoryEntry:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class GameArtifactInventory:
    game_version: str
    entries: tuple[ArtifactInventoryEntry, ...]
    digest: str
    owners_by_path: dict[str, frozenset[str]]

    def to_dict(self) -> dict:
        return {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "game_version": self.game_version,
            "entries": [asdict(entry) for entry in self.entries],
            "digest": self.digest,
        }


def inventory_digest(entries: tuple[ArtifactInventoryEntry, ...]) -> str:
    payload = [asdict(entry) for entry in entries]
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(INVENTORY_DOMAIN_SEPARATOR + encoded).hexdigest()}"


def _walk_artifact_tree(game_root: Path, formal_paths: frozenset[str]) -> tuple[Path, ...]:
    allowed_directories = {PurePosixPath(path).parts[0] for path in formal_paths}
    discovered: list[Path] = []
    if not game_root.exists():
        return ()
    for current, directories, filenames in os.walk(game_root, followlinks=False):
        current_path = Path(current)
        relative_directory = current_path.relative_to(game_root)
        if len(relative_directory.parts) > 1:
            raise BinArtifactContractError(f"Nested artifact directory is not allowed: {relative_directory.as_posix()}")
        if len(relative_directory.parts) == 1 and relative_directory.name not in allowed_directories:
            raise BinArtifactContractError(f"Unknown artifact module directory: {relative_directory.as_posix()}")
        for directory in directories:
            path = current_path / directory
            if is_reparse_point(path):
                raise BinArtifactContractError(f"Artifact directory must not be a link/reparse point: {path}")
            if current_path == game_root and directory not in allowed_directories:
                raise BinArtifactContractError(f"Unknown artifact module directory: {directory}")
            if current_path != game_root:
                raise BinArtifactContractError(
                    f"Nested artifact directory is not allowed: {(relative_directory / directory).as_posix()}"
                )
        for filename in filenames:
            path = current_path / filename
            if is_reparse_point(path):
                raise BinArtifactContractError(f"Artifact file must not be a link/reparse point: {path}")
            if path.suffix != ".yaml":
                raise BinArtifactContractError(f"Unknown file in artifact tree: {path.relative_to(game_root).as_posix()}")
            discovered.append(path)
    return tuple(discovered)


def build_game_artifact_inventory(
    game_version: str,
    config_path: str | Path,
    artifact_root: str | Path = "bin_artifacts",
    *,
    require_canonical_bytes: bool = True,
) -> GameArtifactInventory:
    artifact_root = Path(artifact_root)
    try:
        contract = load_contract(
            config_path,
            game_version,
            artifact_root,
            artifactdir=artifact_root,
        )
        ensure_real_tree(artifact_root, contract.artifact_game_root)
        paths = _walk_artifact_tree(contract.artifact_game_root, contract.formal_paths)
        documents = collect_actual_files(contract, strict=True)
    except (OSError, SnapshotError, TypeError, ValueError) as exc:
        if isinstance(exc, BinArtifactContractError):
            raise
        raise BinArtifactContractError(f"Invalid bin artifact contract for {game_version}: {exc}") from exc

    spellings: dict[str, str] = {}
    entries: list[ArtifactInventoryEntry] = []
    for path in paths:
        key = canonical_key(contract.artifact_game_root, path)
        prior = spellings.setdefault(key.casefold(), key)
        if prior != key:
            raise BinArtifactContractError(f"Case-insensitive artifact collision: {prior!r} and {key!r}")
        raw = path.read_bytes()
        if require_canonical_bytes and canonical_yaml_bytes(documents[key]) != raw:
            raise BinArtifactContractError(f"Artifact is not canonical UTF-8/LF YAML: {key}")
        entries.append(ArtifactInventoryEntry(key, len(raw), hashlib.sha256(raw).hexdigest()))

    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    return GameArtifactInventory(
        game_version=str(game_version),
        entries=ordered,
        digest=inventory_digest(ordered),
        owners_by_path=dict(contract.owners_by_path),
    )
