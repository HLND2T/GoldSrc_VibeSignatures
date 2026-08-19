#!/usr/bin/env python3
"""Download exact Steam depot manifests declared for one or all safe release tags."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

import yaml
from dotenv import load_dotenv

from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from depot_util import append_auth_args, resolve_module_depot_path, run_command, safe_relative_path

DEFAULT_CONFIG_FILE = "download.yaml"
DEFAULT_DEPOT_DIR = "depots"
DEFAULT_OS = "all-platform"


class ConfigError(ValueError):
    pass


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download declared depot manifests for one or all release tags")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-tag", help="download a single release tag")
    target_group.add_argument("-all", action="store_true", help="download every tag declared in the download config")
    parser.add_argument("-config", default=DEFAULT_CONFIG_FILE)
    parser.add_argument("-configyaml", default=None)
    parser.add_argument("-depotdir", default=DEFAULT_DEPOT_DIR)
    parser.add_argument("-os", choices=("windows", "linux", "macos", DEFAULT_OS), default=DEFAULT_OS)
    parser.add_argument("-username", default=os.environ.get("DEPOTDOWNLOADER_STEAM_USERNAME"))
    parser.add_argument("-password", default=os.environ.get("DEPOTDOWNLOADER_STEAM_PASSWORD"))
    parser.add_argument("-remember-password", action="store_true")
    args = parser.parse_args(argv)
    args.remember_password = args.remember_password or bool(args.username and args.password)
    return args


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
    try:
        return safe_relative_path(value, field)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc


def load_module_filelist(configyaml_path: str | Path, basepath: str) -> list[str]:
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
            try:
                relative = resolve_module_depot_path(module, platform, basepath, f"modules[{index}]")
            except ValueError as exc:
                raise ConfigError(str(exc)) from exc
            if relative is not None:
                paths.add(relative)
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
        "-dir",
        str(depot_dir),
        "-filelist",
        str(filelist_path),
    ]
    if os_name == DEFAULT_OS:
        command.append("-all-platforms")
    else:
        command.extend(["-os", str(os_name)])
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
    basepath = _safe_relative(entry["basepath"], "basepath")
    install_dir = Path(depot_dir).joinpath(*PurePosixPath(basepath).parts)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
        handle.write("\n".join(filelist) + "\n")
        filelist_path = Path(handle.name)
    try:
        for depot, manifest in entry["manifests"].items():
            command = build_depotdownloader_command(
                appid=entry["appid"],
                depot=str(depot),
                manifest=str(manifest),
                depot_dir=install_dir,
                os_name=os_name,
                filelist_path=filelist_path,
                branch=entry.get("branch"),
                username=username,
                password=password,
                remember_password=remember_password,
            )
            run_command(command)
        verify_downloaded_files(install_dir, filelist)
    finally:
        filelist_path.unlink(missing_ok=True)


def verify_downloaded_files(install_dir: str | Path, filelist: list[str]) -> None:
    root = Path(install_dir)
    missing = []
    for index, value in enumerate(filelist):
        relative = _safe_relative(value, f"filelist[{index}]")
        target = root.joinpath(*PurePosixPath(relative).parts)
        if not target.is_file():
            missing.append(relative)
    if missing:
        raise ConfigError(f"Downloaded files are missing from {root}: {', '.join(missing)}")


def download_entry(args: argparse.Namespace, entry: dict, depot_dir: str | Path) -> None:
    configyaml = resolve_analysis_config(entry["tag"], args.configyaml)
    filelist = load_module_filelist(configyaml, entry["basepath"])
    download_manifests(
        entry=entry,
        os_name=args.os,
        depot_dir=depot_dir,
        filelist=filelist,
        username=args.username,
        password=args.password,
        remember_password=args.remember_password,
    )
    print(f"Downloaded {len(entry['manifests'])} manifests for {entry['tag']} into {depot_dir}.")


def download_tag(args: argparse.Namespace) -> None:
    entry = find_download_entry(load_downloads(args.config), args.tag)
    download_entry(args, entry, args.depotdir)


def download_all_tags(args: argparse.Namespace) -> int:
    downloads = load_downloads(args.config)
    failures = 0
    for entry in downloads:
        try:
            download_entry(args, entry, args.depotdir)
        except (AnalysisConfigError, ConfigError, yaml.YAMLError, subprocess.CalledProcessError) as exc:
            print(f"Error downloading {entry['tag']}: {exc}")
            failures += 1
    if failures:
        print(f"Failed to download {failures} of {len(downloads)} tags.")
        return 1
    print(f"Downloaded all {len(downloads)} tags into {args.depotdir}.")
    return 0


def main(argv=None) -> int:
    load_dotenv(Path(__file__).with_name(".env"))
    args = parse_args(argv)
    try:
        if args.all:
            return download_all_tags(args)
        download_tag(args)
    except FileNotFoundError:
        print("Error: DepotDownloader executable not found in PATH")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"Error: DepotDownloader failed with exit code {exc.returncode}")
        return exc.returncode or 1
    except (AnalysisConfigError, ConfigError, OSError, yaml.YAMLError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
