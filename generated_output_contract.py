#!/usr/bin/env python3
"""Validate release-owned snapshots, metadata, and gamedata against current source."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

from analysis_config import AnalysisConfigError, iter_analysis_config_tags, validated_tag
from gamedata_contract import (
    GamedataContractError,
    analysis_config_sha256,
    discover_generator_modules,
    generator_contract_sha256,
    validate_gamedata_tree,
)
from gamesymbol_snapshot_lib.codec import SCHEMA_VERSION
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_snapshot_lib.metadata import MetadataContractError, verify_metadata
from gamesymbol_snapshot_lib.operations import check_snapshot_contract
from release_workflow_lib.hashing import sha256_file


class GeneratedOutputContractError(RuntimeError):
    pass


class GeneratedOutputProvenance(NamedTuple):
    analysis_config_sha256: str
    gamedata_manifest_sha256: str


def _expected_gamevers(values: Iterable[str] | None) -> set[str] | None:
    if values is None:
        return None
    normalized = [validated_tag(value) for value in values]
    if len(normalized) != len(set(normalized)):
        raise GeneratedOutputContractError("Generated-output expected gamevers contain duplicates")
    return set(normalized)


def _require_exact_inventory(*, label: str, actual: set[str], expected: set[str]) -> None:
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    raise GeneratedOutputContractError(
        f"Generated-output {label} does not match configs: missing={missing}, extra={extra}"
    )


def validate_generated_output_contract(
    repo_root: str | Path,
    *,
    expected_gamevers: Iterable[str] | None = None,
) -> dict[str, GeneratedOutputProvenance]:
    """Require one complete, current generated-output set for every configured gamever."""

    root = Path(repo_root).resolve()
    try:
        gamevers = tuple(iter_analysis_config_tags(root))
        expected = _expected_gamevers(expected_gamevers)
    except (AnalysisConfigError, TypeError, ValueError) as exc:
        raise GeneratedOutputContractError(f"Unable to resolve generated-output gamevers: {exc}") from exc
    if not gamevers:
        raise GeneratedOutputContractError("Generated-output contract has no configured gamevers")
    configured = set(gamevers)
    if expected is not None and expected != configured:
        raise GeneratedOutputContractError(
            "Generated-output expected gamevers do not match configs: "
            f"missing={sorted(configured - expected)}, extra={sorted(expected - configured)}"
        )

    configs_root = root / "configs"
    actual_configs = (
        {
            path.name
            for path in configs_root.iterdir()
            if path.is_file() and path.suffix == ".yaml" and path.name != "config.yaml"
        }
        if configs_root.is_dir()
        else set()
    )
    _require_exact_inventory(
        label="config inventory",
        actual=actual_configs,
        expected={f"{gamever}.yaml" for gamever in gamevers},
    )

    gamesymbols_root = root / "gamesymbols"
    actual_gamesymbols = (
        {path.name for path in gamesymbols_root.iterdir() if path.is_file() and path.suffix == ".yaml"}
        if gamesymbols_root.is_dir()
        else set()
    )
    expected_gamesymbols = {
        filename for gamever in gamevers for filename in (f"{gamever}.yaml", f"{gamever}.metadata.yaml")
    }
    _require_exact_inventory(
        label="gamesymbol inventory",
        actual=actual_gamesymbols,
        expected=expected_gamesymbols,
    )

    gamedata_root = root / "gamedata"
    actual_gamedata = (
        {path.name for path in gamedata_root.iterdir() if path.is_dir()} if gamedata_root.is_dir() else set()
    )
    _require_exact_inventory(label="gamedata inventory", actual=actual_gamedata, expected=configured)

    try:
        generators = discover_generator_modules(root / "gamedata-generators")
        generator_digest = generator_contract_sha256(generators)
    except (OSError, ValueError) as exc:
        raise GeneratedOutputContractError(f"Unable to load the generated-output generator contract: {exc}") from exc

    provenance = {}
    for gamever in gamevers:
        config = root / "configs" / f"{gamever}.yaml"
        snapshot = gamesymbols_root / f"{gamever}.yaml"
        metadata = gamesymbols_root / f"{gamever}.metadata.yaml"
        try:
            context = check_snapshot_contract(
                gamever,
                bindir=root / "bin",
                artifactdir=root / "bin_artifacts",
                config_path=config,
                snapshot_path=snapshot,
            )
            if context.document["schema_version"] != SCHEMA_VERSION:
                raise GeneratedOutputContractError(
                    f"Generated-output snapshot {gamever} uses schema {context.document['schema_version']}, "
                    f"expected {SCHEMA_VERSION}"
                )
            verify_metadata(
                metadata_path=metadata,
                snapshot_path=snapshot,
                config_path=config,
                game_version=gamever,
            )
            config_sha256 = analysis_config_sha256(config)
            files, manifest_sha256 = validate_gamedata_tree(
                gamedata_root / gamever,
                gamever,
                generators,
                candidate_sha256=sha256_file(snapshot),
                analysis_config_sha256=config_sha256,
                generator_contract_digest=generator_digest,
            )
            if not files:
                raise GeneratedOutputContractError(f"Generated-output gamedata inventory is empty for {gamever}")
            provenance[gamever] = GeneratedOutputProvenance(config_sha256, manifest_sha256)
        except GeneratedOutputContractError:
            raise
        except (GamedataContractError, MetadataContractError, OSError, SnapshotError, ValueError) as exc:
            raise GeneratedOutputContractError(f"Generated-output contract failed for {gamever}: {exc}") from exc

    return provenance


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args(argv)
    try:
        provenance = validate_generated_output_contract(args.repo_root)
    except GeneratedOutputContractError as exc:
        print(f"Error: {exc}")
        return 1
    print(f"Validated generated-output contract for {len(provenance)} game versions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
