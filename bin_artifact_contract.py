"""Formal repository contract for tracked per-symbol analysis artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import argparse
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

import yaml

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.operations import collect_actual_files
from gamesymbol_snapshot_lib.paths import canonical_key, ensure_real_tree, is_reparse_point

INVENTORY_SCHEMA_VERSION = 1
INVENTORY_DOMAIN_SEPARATOR = b"bin-artifact-inventory:v1\n"
REPOSITORY_DOMAIN_SEPARATOR = b"bin-artifact-repository:v1\n"


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


@dataclass(frozen=True)
class RepositoryArtifactInventory:
    gamevers: tuple[GameArtifactInventory, ...]
    digest: str

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(
            f"bin_artifacts/{inventory.game_version}/{entry.path}"
            for inventory in self.gamevers
            for entry in inventory.entries
        )


def inventory_digest(entries: tuple[ArtifactInventoryEntry, ...]) -> str:
    payload = [asdict(entry) for entry in entries]
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(INVENTORY_DOMAIN_SEPARATOR + encoded).hexdigest()}"


def _validate_canonical_text_bytes(raw: bytes, key: str) -> None:
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or not raw.endswith(b"\n") or b"\x00" in raw:
        raise BinArtifactContractError(f"Artifact is not canonical UTF-8/LF YAML: {key}")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BinArtifactContractError(f"Artifact is not canonical UTF-8/LF YAML: {key}") from exc


def _walk_artifact_tree(
    game_root: Path,
    formal_paths: frozenset[str],
    *,
    allow_non_artifact_files: bool,
) -> tuple[Path, ...]:
    allowed_directories = {PurePosixPath(path).parts[0] for path in formal_paths}
    discovered: list[Path] = []
    if not game_root.exists():
        return ()
    for current, directories, filenames in os.walk(game_root, followlinks=False):
        current_path = Path(current)
        relative_directory = current_path.relative_to(game_root)
        if not allow_non_artifact_files and len(relative_directory.parts) > 1:
            raise BinArtifactContractError(f"Nested artifact directory is not allowed: {relative_directory.as_posix()}")
        if (
            not allow_non_artifact_files
            and len(relative_directory.parts) == 1
            and relative_directory.name not in allowed_directories
        ):
            raise BinArtifactContractError(f"Unknown artifact module directory: {relative_directory.as_posix()}")
        for directory in directories:
            path = current_path / directory
            if is_reparse_point(path):
                raise BinArtifactContractError(f"Artifact directory must not be a link/reparse point: {path}")
            if not allow_non_artifact_files and current_path == game_root and directory not in allowed_directories:
                raise BinArtifactContractError(f"Unknown artifact module directory: {directory}")
            if not allow_non_artifact_files and current_path != game_root:
                raise BinArtifactContractError(
                    f"Nested artifact directory is not allowed: {(relative_directory / directory).as_posix()}"
                )
        for filename in filenames:
            path = current_path / filename
            if is_reparse_point(path):
                raise BinArtifactContractError(f"Artifact file must not be a link/reparse point: {path}")
            if path.suffix != ".yaml":
                if allow_non_artifact_files:
                    continue
                raise BinArtifactContractError(f"Unknown file in artifact tree: {path.relative_to(game_root).as_posix()}")
            discovered.append(path)
    return tuple(discovered)


def build_game_artifact_inventory(
    game_version: str,
    config_path: str | Path,
    artifact_root: str | Path = "bin_artifacts",
    *,
    require_canonical_bytes: bool = True,
    allow_non_artifact_files: bool = False,
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
        paths = _walk_artifact_tree(
            contract.artifact_game_root,
            contract.formal_paths,
            allow_non_artifact_files=allow_non_artifact_files,
        )
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
        if require_canonical_bytes:
            _validate_canonical_text_bytes(raw, key)
        entries.append(ArtifactInventoryEntry(key, len(raw), hashlib.sha256(raw).hexdigest()))

    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    return GameArtifactInventory(
        game_version=str(game_version),
        entries=ordered,
        digest=inventory_digest(ordered),
        owners_by_path=dict(contract.owners_by_path),
    )


def _configured_gamevers(repo_root: Path) -> tuple[str, ...]:
    try:
        document = yaml.safe_load((repo_root / "configs/config.yaml").read_bytes()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise BinArtifactContractError(f"Unable to read configs/config.yaml: {exc}") from exc
    gamevers = document.get("gamevers")
    if not isinstance(gamevers, list) or not gamevers or any(not isinstance(tag, str) or not tag for tag in gamevers):
        raise BinArtifactContractError("configs/config.yaml must declare a non-empty string gamevers list")
    if len({tag.casefold() for tag in gamevers}) != len(gamevers):
        raise BinArtifactContractError("configs/config.yaml contains duplicate/case-colliding gamevers")
    return tuple(sorted(gamevers))


def _tracked_paths(repo_root: Path, pathspec: str) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", pathspec],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise BinArtifactContractError(
            f"Unable to enumerate tracked {pathspec}: {result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return {item.decode("utf-8") for item in result.stdout.split(b"\0") if item}


def validate_repository_artifact_contract(
    repo_root: str | Path = ".",
    *,
    require_tracked: bool = True,
) -> RepositoryArtifactInventory:
    repo_root = Path(repo_root).resolve()
    artifact_root = repo_root / "bin_artifacts"
    gamevers = _configured_gamevers(repo_root)
    if not artifact_root.is_dir():
        raise BinArtifactContractError(f"Tracked artifact root is missing: {artifact_root}")
    inventories = tuple(
        build_game_artifact_inventory(gamever, repo_root / "configs" / f"{gamever}.yaml", artifact_root)
        for gamever in gamevers
    )
    expected_directories = {inventory.game_version for inventory in inventories if inventory.entries}
    actual_directories = {path.name for path in artifact_root.iterdir() if path.is_dir()}
    actual_files = {path.name for path in artifact_root.iterdir() if path.is_file()}
    if actual_files or actual_directories != expected_directories:
        raise BinArtifactContractError(
            "bin_artifacts gamever inventory mismatch: "
            f"expected={sorted(expected_directories)!r}; actual={sorted(actual_directories)!r}; "
            f"files={sorted(actual_files)!r}"
        )
    digest_payload = [
        {"game_version": inventory.game_version, "digest": inventory.digest} for inventory in inventories
    ]
    encoded = json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    repository = RepositoryArtifactInventory(
        gamevers=inventories,
        digest=f"sha256:{hashlib.sha256(REPOSITORY_DOMAIN_SEPARATOR + encoded).hexdigest()}",
    )
    if require_tracked:
        tracked = _tracked_paths(repo_root, "bin_artifacts")
        if tracked != set(repository.paths):
            raise BinArtifactContractError(
                "Tracked bin_artifacts inventory mismatch: "
                f"missing={sorted(set(repository.paths) - tracked)!r}; extra={sorted(tracked - set(repository.paths))!r}"
            )
        tracked_legacy = _tracked_paths(repo_root, "bin/**/*.yaml")
        if tracked_legacy:
            raise BinArtifactContractError(f"Legacy bin YAML must not be tracked: {sorted(tracked_legacy)!r}")
    return repository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args(argv)
    try:
        inventory = validate_repository_artifact_contract(args.repo_root)
    except (BinArtifactContractError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    print(
        f"Repository artifact contract valid: gamevers={len(inventory.gamevers)}; "
        f"files={len(inventory.paths)}; digest={inventory.digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
