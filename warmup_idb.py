#!/usr/bin/env python3
"""Warm every configured GoldSrc IDA database for one GAMEVER in place.

Each configured ``bin/<tag>/<module>/<binary>`` is warmed by a separate bare-idalib
worker process (``idb_warm_worker.py``) so no idalib-mcp port is contended for, and the
warmed database lands beside the binary that analysis later opens under the strict
restored-database policy. Blob-backed game versions are decrypted first with the same
helper analysis uses, so warming targets the decrypted PE rather than the raw blob.

The producer is idempotent: a binary whose primary database already validates is
skipped, and ``-force`` invalidates and re-warms every configured binary. Concurrent
workers are bounded by ``-max-concurrency`` (or ``$IDB_WARMUP_MAX_CONCURRENCY``), and
``$IDB_WARMUP_MAX_MEMORY_MIB`` enables aggregate memory admission.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from analysis_config import AnalysisConfigError, resolve_analysis_config
from analysis_planner import PLATFORMS, AnalysisPlanError, load_config
from ida_analyze_bin import get_binary_path, prepare_analysis_binary
from ida_database_paths import existing_database_lock, validate_database_file_set
from idb_cache import (
    DEFAULT_WORKER_TIMEOUT_SECONDS,
    IdbCacheError,
    build_binary_identity,
    build_cache_identity,
    probe_ida_kernel_version,
    warm_group,
)

DEFAULT_BIN_DIR = "bin"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Warm configured GoldSrc IDA databases in place")
    parser.add_argument("-gamever", required=True)
    parser.add_argument("-python", dest="python_exe", required=True, help="Interpreter with idalib (idapro)")
    parser.add_argument("-bindir", default=DEFAULT_BIN_DIR)
    parser.add_argument("-config", default=None)
    parser.add_argument("-platform", choices=(*PLATFORMS, "all-platform"), default="all-platform")
    parser.add_argument(
        "-max-concurrency",
        dest="max_concurrency",
        type=int,
        default=None,
        help="Max concurrent workers (default: $IDB_WARMUP_MAX_CONCURRENCY or 2)",
    )
    parser.add_argument(
        "-worker-timeout-seconds",
        dest="worker_timeout_seconds",
        type=float,
        default=DEFAULT_WORKER_TIMEOUT_SECONDS,
        help=f"Timeout for each worker process (default: {DEFAULT_WORKER_TIMEOUT_SECONDS:g} seconds)",
    )
    parser.add_argument("-force", action="store_true", help="Invalidate and re-warm every configured database")
    return parser.parse_args(argv)


def selected_platforms(platform_filter: str) -> tuple[str, ...]:
    return PLATFORMS if platform_filter == "all-platform" else (platform_filter,)


def declared_binaries(bindir, gamever, modules, platform_filter):
    """Return ``(module, platform, source path)`` per declared platform binary, in config order."""
    entries = []
    for module in modules:
        for platform in selected_platforms(platform_filter):
            binary_name = module.get(f"module_{platform}")
            if not binary_name:
                continue
            entries.append(
                (module["name"], platform, Path(get_binary_path(bindir, gamever, module["name"], binary_name)))
            )
    return entries


def has_warm_database(binary: Path) -> bool:
    """Report whether a validated primary database already exists without an active lock."""
    if existing_database_lock(binary) is not None:
        return False
    try:
        validate_database_file_set(binary)
    except (OSError, ValueError):
        return False
    return True


def _prepared_entries(declared):
    prepared = []
    for module, platform, source in declared:
        try:
            prepared.append((module, platform, prepare_analysis_binary(source, platform)))
        except (OSError, ValueError) as exc:
            raise IdbCacheError(f"{module}/{platform}: {exc}") from exc
    return prepared


def _platform_groups(entries):
    groups: dict[str, list] = {}
    for entry in entries:
        groups.setdefault(entry[1], []).append(entry)
    return groups


def _identity(*, gamever, binary_root, entries, python_exe):
    binaries = [
        build_binary_identity(
            workspace_root=binary_root,
            module=module,
            platform=platform,
            relative_path=binary.relative_to(binary_root).as_posix(),
        )
        for module, platform, binary in entries
    ]
    return build_cache_identity(
        tag=gamever,
        ida_runtime={"kernel_version": probe_ida_kernel_version(python_exe)},
        binaries=binaries,
        warm_worker_path=Path(__file__).with_name("idb_warm_worker.py"),
    )


def main(argv=None):
    args = parse_args(argv)
    python_exe = shutil.which(args.python_exe)
    if not python_exe:
        print(f"Error: interpreter with idalib not found: {args.python_exe}")
        return 1
    try:
        config_path = resolve_analysis_config(args.gamever, args.config)
        _document, modules = load_config(config_path)
        declared = declared_binaries(args.bindir, args.gamever, modules, args.platform)
        prepared = _prepared_entries(declared)
    except (AnalysisConfigError, AnalysisPlanError, IdbCacheError) as exc:
        print(f"Error: {exc}")
        return 1
    if not prepared:
        print(f"Error: {args.gamever} declares no {args.platform} binaries to warm")
        return 1

    binary_root = Path(args.bindir) / args.gamever
    pending = [entry for entry in prepared if args.force or not has_warm_database(entry[2])]
    skipped = len(prepared) - len(pending)
    if not pending:
        print(f"Warmup: {len(prepared)} configured, {skipped} already warm; nothing to do.")
        return 0

    print(f"Warmup: {len(prepared)} configured, {skipped} already warm, {len(pending)} to warm")
    failed = 0
    for platform, entries in _platform_groups(pending).items():
        try:
            warm_group(
                identity=_identity(
                    gamever=args.gamever,
                    binary_root=binary_root,
                    entries=entries,
                    python_exe=python_exe,
                ),
                workspace_root=binary_root,
                ida_python_executable=python_exe,
                max_concurrency=args.max_concurrency,
                worker_timeout_seconds=args.worker_timeout_seconds,
            )
        except (IdbCacheError, OSError, ValueError) as exc:
            print(f"Error: {platform}: {exc}")
            failed += len(entries)
    if failed:
        print(f"Warmup failed: {failed} of {len(pending)} databases were not warmed")
        return 1
    print(f"Warmup complete: {len(pending)} warmed, {skipped} already warm")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
