#!/usr/bin/env python3
"""Run strict local gamedata generators against a SymbolStore."""

from __future__ import annotations

import argparse
from pathlib import Path

from analysis_config import AnalysisConfigError, resolve_analysis_config
from gamedata_contract import (
    GamedataContractError,
    GeneratorContext,
    build_gamedata_manifest,
    discover_generator_modules,
    generator_contract_sha256,
    write_gamedata_manifest,
    validate_output_tree,
)
from gamesymbol_store import SymbolStoreError, open_snapshot_store
from release_workflow_lib.hashing import sha256_file


def generate_gamedata(*, gamever, snapshot_path, config_path, modules_dir, output_root):
    output_root = Path(output_root)
    if output_root.exists():
        raise GamedataContractError(f"Output root must be new: {output_root}")
    store = open_snapshot_store(snapshot_path=snapshot_path, config_path=config_path, expected_game_version=gamever)
    modules = discover_generator_modules(modules_dir)
    output_root.mkdir(parents=True)
    context = GeneratorContext(store.game_version, store.binaries)
    for contract in modules:
        module_root = output_root / contract.directory
        module_root.mkdir(parents=True)
        try:
            if contract.api_version == 2:
                contract.module.update(store, module_root, context=context)
            else:
                contract.module.update(store, module_root)
        except Exception as exc:
            raise GamedataContractError(f"Generator {contract.directory} failed: {exc}") from exc
    payload_files = validate_output_tree(output_root, gamever, modules)
    generator_digest = generator_contract_sha256(modules)
    manifest = build_gamedata_manifest(
        gamever=gamever,
        candidate_sha256=sha256_file(snapshot_path),
        analysis_config_sha256=sha256_file(config_path),
        generator_contract_digest=generator_digest,
        payload_files=payload_files,
    )
    manifest_sha256 = write_gamedata_manifest(output_root, manifest)
    files = [
        *payload_files,
        {
            "path": f"gamedata/{gamever}/gamedata-manifest.json",
            "size": (output_root / "gamedata-manifest.json").stat().st_size,
            "sha256": manifest_sha256,
        },
    ]
    files.sort(key=lambda item: item["path"])
    return {
        "generator_contract_sha256": generator_digest,
        "gamedata_manifest_sha256": manifest_sha256,
        "payload_files": payload_files,
        "files": files,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate contained GoldSrc gamedata")
    parser.add_argument("-gamever", required=True)
    parser.add_argument("-snapshot", required=True)
    parser.add_argument("-configyaml", default=None)
    parser.add_argument("-modulesdir", default="gamedata-generators")
    parser.add_argument("-outputdir", default=None)
    args = parser.parse_args(argv)
    try:
        config = resolve_analysis_config(args.gamever, args.configyaml)
        generate_gamedata(
            gamever=args.gamever,
            snapshot_path=args.snapshot,
            config_path=config,
            modules_dir=args.modulesdir,
            output_root=args.outputdir or Path("gamedata") / args.gamever,
        )
    except (AnalysisConfigError, GamedataContractError, SymbolStoreError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
