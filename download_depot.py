#!/usr/bin/env python3
"""Download exact Steam depot manifests declared for a safe release tag."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

import yaml

from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from depot_util import append_auth_args, run_command

DEFAULT_CONFIG_FILE = "download.yaml"
DEFAULT_DEPOT_DIR = "depots"
DEFAULT_OS = "all-platform"


class ConfigError(ValueError):
    pass


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download declared depot manifests for a release tag")
    parser.add_argument("-tag", required=True)
    parser.add_argument("-config", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("-configyaml", default=None)
    parser.add_argument("-depotdir", default=DEFAULT_DEPOT_DIR)
    parser.add_argument("-os", default=DEFAULT_OS)
    parser.add_argument("-username", default=os.environ.get("DEPOTDOWNLOADER_STEAM_USERNAME"))
    parser.add_argument("-password", default=os.environ.get("DEPOTDOWNLOADER_STEAM_PASSWORD"))
    parser.add_argument("-remember-password", action="store_true")
    return parser.parse_args(argv)


def load_downloads(config_path: str | Path) -> list[dict]:
    path = Path(config_path)
    if not path.is_file():
        raise ConfigError(f"Download config file not found: {path}")
    try:
        document = yaml.safe_load(path.read_bytes()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in download config: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("downloads"), list):
        raise ConfigError("Download config must contain a downloads list")
    entries = document["downloads"]
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"downloads[{index}] must be a mapping")
        tag = entry.get("tag")
        try:
            validated_tag(tag)
        except AnalysisConfigError as exc:
            raise ConfigError(f"downloads[{index}]: {exc}") from exc
        if tag in seen:
            raise ConfigError(f"Duplicate download tag: {tag}")
        seen.add(tag)
        if not isinstance(entry.get("appid"), int) or isinstance(entry["appid"], bool) or entry["appid"] <= 0:
            raise ConfigError(f"downloads[{index}].appid must be a positive integer")
        if not isinstance(entry.get("basepath"), str) or not entry["basepath"]:
            raise ConfigError(f"downloads[{index}].basepath must be a non-empty string")
        _safe_relative(entry["basepath"], f"downloads[{index}].basepath")
        if "major_update" in entry and not isinstance(entry["major_update"], bool):
            raise ConfigError(f"downloads[{index}].major_update must be a boolean")
        manifests = entry.get("manifests")
        if not isinstance(manifests, dict) or not manifests:
            raise ConfigError(f"downloads[{index}].manifests must be a non-empty mapping")
        for depot, manifest in manifests.items():
            if not str(depot).isdigit() or not str(manifest).isdigit():
                raise ConfigError(f"downloads[{index}].manifests must contain numeric depot and manifest ids")
    return entries


def find_download_entry(downloads: list[dict], tag: str) -> dict:
    validated_tag(tag)
    matches = [entry for entry in downloads if entry.get("tag") == tag]
    if len(matches) != 1:
        detail = "not found" if not matches else "duplicated"
        raise ConfigError(f"Download tag {tag!r} is {detail}")
    return matches[0]


def _safe_relative(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ConfigError(f"{field} must be a non-empty relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ConfigError(f"{field} is unsafe: {value!r}")
    return path.as_posix()


def load_module_filelist(configyaml_path: str | Path) -> list[str]:
    path = Path(configyaml_path)
    try:
        document = yaml.safe_load(path.read_bytes()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Unable to read module config {path}: {exc}") from exc
    modules = document.get("modules") if isinstance(document, dict) else None
    if not isinstance(modules, list):
        raise ConfigError("Analysis config must contain a modules list")
    paths: set[str] = set()
    for index, module in enumerate(modules):
        if not isinstance(module, dict):
            raise ConfigError(f"modules[{index}] must be a mapping")
        for platform in ("windows", "linux"):
            value = module.get(f"path_{platform}")
            if value is not None:
                paths.add(_safe_relative(value, f"modules[{index}].path_{platform}"))
    if not paths:
        raise ConfigError("Analysis config declares no module binaries")
    return sorted(paths)


def build_depotdownloader_command(
    *,
    appid: int,
    depot: str,
    manifest: str,
    depot_dir: str | Path,
    os_name: str,
    filelist_path: str | Path,
    branch: str | None = None,
    username: str | None = None,
    password: str | None = None,
    remember_password: bool = False,
) -> list[str]:
    command = [
        "DepotDownloader",
        "-app",
        str(appid),
        "-depot",
        str(depot),
        "-manifest",
        str(manifest),
        "-os",
        str(os_name),
        "-dir",
        str(depot_dir),
        "-filelist",
        str(filelist_path),
    ]
    if branch:
        command.extend(["-branch", branch])
    append_auth_args(command, username, password, remember_password)
    return command


def download_manifests(
    *,
    entry: dict,
    os_name: str,
    depot_dir: str | Path,
    filelist: list[str],
    username: str | None = None,
    password: str | None = None,
    remember_password: bool = False,
) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        handle.write("\n".join(filelist) + "\n")
        filelist_path = Path(handle.name)
    try:
        for depot, manifest in entry["manifests"].items():
            command = build_depotdownloader_command(
                appid=entry["appid"],
                depot=str(depot),
                manifest=str(manifest),
                depot_dir=depot_dir,
                os_name=os_name,
                filelist_path=filelist_path,
                branch=entry.get("branch"),
                username=username,
                password=password,
                remember_password=remember_password,
            )
            run_command(command)
    finally:
        filelist_path.unlink(missing_ok=True)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        configyaml = resolve_analysis_config(args.tag, args.configyaml)
        entry = find_download_entry(load_downloads(args.config), args.tag)
        filelist = load_module_filelist(configyaml)
        download_manifests(
            entry=entry,
            os_name=args.os,
            depot_dir=args.depotdir,
            filelist=filelist,
            username=args.username,
            password=args.password,
            remember_password=args.remember_password,
        )
    except FileNotFoundError:
        print("Error: DepotDownloader executable not found in PATH")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"Error: DepotDownloader failed with exit code {exc.returncode}")
        return exc.returncode or 1
    except (AnalysisConfigError, ConfigError, OSError, yaml.YAMLError) as exc:
        print(f"Error: {exc}")
        return 1
    print(f"Downloaded {len(entry['manifests'])} manifests for {args.tag} into {args.depotdir}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
