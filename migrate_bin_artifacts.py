#!/usr/bin/env python3
"""Copy legacy per-symbol YAML from bin into the tracked bin_artifacts root."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import yaml

from bin_artifact_contract import BinArtifactContractError, build_game_artifact_inventory
from gamesymbol_snapshot_lib.operations import _atomic_write
from gamesymbol_snapshot_lib.paths import ensure_real_tree, is_reparse_point


class ArtifactMigrationError(ValueError):
    pass


@dataclass(frozen=True)
class MigrationResult:
    gamevers: int
    files: int


def _configured_gamevers(repo_root: Path) -> tuple[str, ...]:
    try:
        document = yaml.safe_load((repo_root / "configs" / "config.yaml").read_bytes()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ArtifactMigrationError(f"Unable to read game-version index: {exc}") from exc
    gamevers = document.get("gamevers")
    if not isinstance(gamevers, list) or not gamevers or any(not isinstance(tag, str) for tag in gamevers):
        raise ArtifactMigrationError("configs/config.yaml must declare a non-empty string gamevers list")
    if len(set(gamevers)) != len(gamevers):
        raise ArtifactMigrationError("configs/config.yaml contains duplicate gamevers")
    return tuple(sorted(gamevers))


def _validate_global_yaml_scope(root: Path, configured: set[str], label: str) -> None:
    if not root.is_dir():
        raise ArtifactMigrationError(f"{label} root does not exist: {root}")
    if is_reparse_point(root):
        raise ArtifactMigrationError(f"{label} root must not be a link/reparse point: {root}")
    for path in root.rglob("*.yaml"):
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise ArtifactMigrationError(f"{label} path escapes its root: {path}") from exc
        if len(relative.parts) != 3 or relative.parts[0] not in configured:
            raise ArtifactMigrationError(f"Unexpected {label} YAML path: {relative.as_posix()}")


def migrate_bin_artifacts(repo_root: str | Path, *, write: bool = False) -> MigrationResult:
    repo_root = Path(repo_root).resolve()
    binary_root = repo_root / "bin"
    artifact_root = repo_root / "bin_artifacts"
    gamevers = _configured_gamevers(repo_root)
    _validate_global_yaml_scope(binary_root, set(gamevers), "legacy bin")
    if artifact_root.exists():
        ensure_real_tree(repo_root, artifact_root)

    source_inventories = {}
    try:
        for gamever in gamevers:
            config = repo_root / "configs" / f"{gamever}.yaml"
            source_inventories[gamever] = build_game_artifact_inventory(
                gamever,
                config,
                binary_root,
                allow_non_artifact_files=True,
            )
    except BinArtifactContractError as exc:
        raise ArtifactMigrationError(str(exc)) from exc

    if write:
        for gamever, inventory in source_inventories.items():
            for entry in inventory.entries:
                source = binary_root / gamever / Path(entry.path)
                target = artifact_root / gamever / Path(entry.path)
                if target.exists() and target.read_bytes() != source.read_bytes():
                    raise ArtifactMigrationError(f"Refusing to overwrite different destination artifact: {target}")
                _atomic_write(target, source.read_bytes())

        _validate_global_yaml_scope(artifact_root, set(gamevers), "destination")
        for gamever, source_inventory in source_inventories.items():
            config = repo_root / "configs" / f"{gamever}.yaml"
            destination_inventory = build_game_artifact_inventory(gamever, config, artifact_root)
            if destination_inventory.entries != source_inventory.entries:
                raise ArtifactMigrationError(f"Source/destination artifact inventory differs for {gamever}")

    return MigrationResult(len(gamevers), sum(len(item.entries) for item in source_inventories.values()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--write", action="store_true", help="Write the validated destination tree")
    args = parser.parse_args(argv)
    try:
        result = migrate_bin_artifacts(args.repo_root, write=args.write)
    except (ArtifactMigrationError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    mode = "migrated" if args.write else "validated"
    print(f"Artifact migration {mode}: gamevers={result.gamevers}; files={result.files}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
