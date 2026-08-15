#!/usr/bin/env python3
"""Copy configured GoldSrc binaries into bin/<tag>/<module>."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path, PurePosixPath

import yaml

from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from binary_format import BinaryFormatError, validate_binary

DEFAULT_DEPOT_DIR = "depots"
DEFAULT_BIN_DIR = "bin"
CHECKONLY_MISSING_EXIT = 1
CHECKONLY_ERROR_EXIT = 2
PLATFORMS = ("windows", "linux")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Copy configured GoldSrc depot binaries")
    parser.add_argument("-gamever", required=True)
    parser.add_argument("-bindir", default=DEFAULT_BIN_DIR)
    parser.add_argument("-depotdir", default=DEFAULT_DEPOT_DIR)
    parser.add_argument("-platform", choices=["windows", "linux", "all-platform"], default="all-platform")
    parser.add_argument("-config", default=None)
    parser.add_argument("-checkonly", action="store_true")
    return parser.parse_args(argv)


def _safe_component(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or "/" in value or "\\" in value:
        raise ValueError(f"{field} must be one safe path component")
    return value


def _safe_source_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError(f"{field} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{field} is unsafe: {value!r}")
    return path.as_posix()


def parse_config(config_path: str | Path) -> list[dict]:
    try:
        document = yaml.safe_load(Path(config_path).read_bytes()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Unable to read analysis config: {exc}") from exc
    modules = document.get("modules") if isinstance(document, dict) else None
    if not isinstance(modules, list):
        raise TypeError("Analysis config must contain a modules list")
    normalized = []
    seen: dict[str, str] = {}
    for index, module in enumerate(modules):
        if not isinstance(module, dict):
            raise TypeError(f"modules[{index}] must be a mapping")
        name = _safe_component(module.get("name"), f"modules[{index}].name")
        prior = seen.setdefault(name.casefold(), name)
        if prior != name:
            raise ValueError(f"Case-insensitive module collision: {prior!r} and {name!r}")
        item = {"name": name}
        for platform in PLATFORMS:
            value = module.get(f"path_{platform}")
            item[f"path_{platform}"] = (
                None if value is None else _safe_source_path(value, f"modules[{index}].path_{platform}")
            )
            binary_name = module.get(f"module_{platform}")
            if item[f"path_{platform}"] is not None:
                item[f"module_{platform}"] = _safe_component(binary_name, f"modules[{index}].module_{platform}")
            else:
                item[f"module_{platform}"] = None
        binary_names = [item[f"module_{platform}"] for platform in PLATFORMS if item[f"module_{platform}"] is not None]
        if len({name.casefold() for name in binary_names}) != len(binary_names):
            raise ValueError(f"modules[{index}] platform binaries collide in one target directory")
        normalized.append(item)
    return normalized


def selected_platforms(platform_filter: str | None) -> tuple[str, ...]:
    return PLATFORMS if platform_filter in {None, "all-platform"} else (platform_filter,)


def iter_module_entries(module, bin_dir, gamever, platform_filter, depot_dir):
    tag = validated_tag(gamever)
    entries = []
    for platform in selected_platforms(platform_filter):
        source_rel = module.get(f"path_{platform}")
        if not source_rel:
            continue
        source = Path(depot_dir).joinpath(*PurePosixPath(source_rel).parts)
        target = Path(bin_dir) / tag / module["name"] / module[f"module_{platform}"]
        entries.append(
            {
                "name": module["name"],
                "platform": platform,
                "source_path": str(source),
                "target_path": str(target),
            }
        )
    return entries


def check_module_targets(module, bin_dir, gamever, platform_filter, depot_dir):
    ready = missing = 0
    for entry in iter_module_entries(module, bin_dir, gamever, platform_filter, depot_dir):
        target = Path(entry["target_path"])
        if not target.is_file():
            missing += 1
            continue
        try:
            validate_binary(target, entry["platform"])
        except BinaryFormatError:
            missing += 1
        else:
            ready += 1
    return ready, missing


def process_module(module, bin_dir, gamever, platform_filter, depot_dir):
    success = failed = 0
    for entry in iter_module_entries(module, bin_dir, gamever, platform_filter, depot_dir):
        source = Path(entry["source_path"])
        target = Path(entry["target_path"])
        try:
            validate_binary(source, entry["platform"])
            if target.exists():
                validate_binary(target, entry["platform"])
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                validate_binary(target, entry["platform"])
            success += 1
        except (OSError, BinaryFormatError) as exc:
            print(f"Error: {entry['name']}/{entry['platform']}: {exc}")
            failed += 1
    return success, failed


def main(argv=None):
    args = parse_args(argv)
    error_exit = CHECKONLY_ERROR_EXIT if args.checkonly else 1
    try:
        config_path = resolve_analysis_config(args.gamever, args.config)
        modules = parse_config(config_path)
    except (AnalysisConfigError, TypeError, ValueError) as exc:
        print(f"Error: {exc}")
        return error_exit
    if args.checkonly:
        ready = missing = 0
        for module in modules:
            module_ready, module_missing = check_module_targets(
                module, args.bindir, args.gamever, args.platform, args.depotdir
            )
            ready += module_ready
            missing += module_missing
        print(f"Check-only summary: {ready} ready, {missing} missing")
        return CHECKONLY_MISSING_EXIT if missing else 0
    if not Path(args.depotdir).is_dir():
        print(f"Error: Depot directory not found: {args.depotdir}")
        return 1
    success = failed = 0
    for module in modules:
        module_success, module_failed = process_module(module, args.bindir, args.gamever, args.platform, args.depotdir)
        success += module_success
        failed += module_failed
    print(f"Completed: {success} successful, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
