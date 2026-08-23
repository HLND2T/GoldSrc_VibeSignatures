#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import ctypes
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from binary_format import inspect_binary
from ida_analyze_bin import DEFAULT_HOST, DEFAULT_PORT, IdaMcpLifecycle, _parse_py_eval_json
from ida_database_paths import database_paths, existing_database_lock, validate_database_file_set, validate_plain_file
from ida_mcp_session import open_ida_mcp_session
from idb_cache import IdbCacheError, load_cache_identity
from release_workflow_lib.hashing import sha256_file, write_canonical_json

_WINDOWS_JOB_HANDLE = None
RUNTIME_IDENTITY_PY_EVAL = (
    "import json\n"
    "import idaapi\n"
    "import ida_ida\n"
    "result = json.dumps({\n"
    "    'kernel_version': str(idaapi.get_kernel_version()),\n"
    "    'processor': str(ida_ida.inf_get_procname()),\n"
    "    'bitness': 64 if ida_ida.inf_is_64bit() else 32,\n"
    "    'file_type_name': str(idaapi.get_file_type_name()),\n"
    "})\n"
)


def _apply_memory_limit(limit_mb: int) -> None:
    if limit_mb < 256:
        raise IdbCacheError("Warm worker memory limit must be at least 256 MiB")
    limit_bytes = limit_mb * 1024 * 1024
    if os.name != "nt":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
        return

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_ulong),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_ulong),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_ulong),
            ("SchedulingClass", ctypes.c_ulong),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong]
    kernel32.SetInformationJobObject.restype = ctypes.c_int
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.AssignProcessToJobObject.restype = ctypes.c_int
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise IdbCacheError(f"Unable to create warm worker Job Object: {ctypes.get_last_error()}")
    information = ExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000 | 0x00000200
    information.JobMemoryLimit = limit_bytes
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(information), ctypes.sizeof(information)):
        raise IdbCacheError(f"Unable to set warm worker Job Object limit: {ctypes.get_last_error()}")
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        raise IdbCacheError(f"Unable to assign warm worker Job Object: {ctypes.get_last_error()}")
    global _WINDOWS_JOB_HANDLE
    _WINDOWS_JOB_HANDLE = job


@contextmanager
def exclusive_file_lock(path: str | Path, timeout_seconds: float = 120.0):
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    deadline = time.monotonic() + timeout_seconds
    acquired = False
    try:
        while not acquired:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    if handle.tell() == handle.seek(0, os.SEEK_END):
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise IdbCacheError(f"Timed out acquiring IDA MCP port lock: {lock_path}")
                time.sleep(0.1)
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _loader_path(ida_root: Path, loader_name: str) -> Path:
    suffixes = (".dll", ".so", ".dylib")
    matches = [ida_root / "loaders" / f"{loader_name}{suffix}" for suffix in suffixes]
    existing = [path for path in matches if path.is_file()]
    if len(existing) != 1:
        raise IdbCacheError(f"Unable to resolve one pinned IDA loader for {loader_name}: {existing}")
    return validate_plain_file(existing[0], context="IDA loader module")


def probe_runtime_contract(
    *, ida_root: str | Path, kernel_version: str, binary_path: str | Path, plugins: tuple[str, ...] = ()
) -> dict:
    root = Path(ida_root).resolve()
    if not root.is_dir():
        raise IdbCacheError(f"IDA root is missing: {root}")
    binary = inspect_binary(binary_path)
    loader_name = "pe" if binary.container == "PE" else "elf"
    plugin_records = []
    for plugin_name in sorted(plugins, key=lambda value: value.encode("utf-8")):
        if not plugin_name or Path(plugin_name).name != plugin_name:
            raise IdbCacheError(f"Invalid IDA plugin allowlist name: {plugin_name!r}")
        plugin = validate_plain_file(root / "plugins" / plugin_name, context="IDA plugin")
        plugin_records.append({"name": plugin_name, "sha256": sha256_file(plugin)})
    return {
        "kernel_version": str(kernel_version).strip(),
        "processor": "metapc",
        "bitness": binary.bits,
        "file_type": binary.container,
        "loader_name": loader_name,
        "loader_module_sha256": sha256_file(_loader_path(root, loader_name)),
        "plugins": plugin_records,
    }


async def _query_opened_runtime(binary: Path) -> dict:
    async with open_ida_mcp_session(
        DEFAULT_HOST,
        DEFAULT_PORT,
        expected_binary=binary,
        auto_started=True,
    ) as session:
        payload = _parse_py_eval_json(await session.call_tool("py_eval", {"code": RUNTIME_IDENTITY_PY_EVAL}))
    if not isinstance(payload, dict) or set(payload) != {
        "kernel_version",
        "processor",
        "bitness",
        "file_type_name",
    }:
        raise IdbCacheError("Warm worker could not observe the opened IDA runtime identity")
    return payload


def _observed_runtime(binary: Path, expected: dict) -> dict:
    opened = asyncio.run(_query_opened_runtime(binary))
    label = str(opened["file_type_name"]).upper()
    file_type = "ELF" if "ELF" in label else "PE" if "PE" in label or "PORTABLE EXECUTABLE" in label else ""
    if not file_type:
        raise IdbCacheError(f"Unsupported opened IDA file type: {opened['file_type_name']!r}")
    ida_root_value = os.environ.get("IDADIR")
    if not ida_root_value:
        raise IdbCacheError("IDADIR is required to bind the observed loader/plugin identity")
    plugin_names = tuple(plugin["name"] for plugin in expected["plugins"])
    runtime = probe_runtime_contract(
        ida_root=ida_root_value,
        kernel_version=str(opened["kernel_version"]),
        binary_path=binary,
        plugins=plugin_names,
    )
    runtime["processor"] = str(opened["processor"])
    runtime["bitness"] = opened["bitness"]
    runtime["file_type"] = file_type
    runtime["loader_name"] = "pe" if file_type == "PE" else "elf"
    return runtime


def _cleanup_database(binary: Path) -> None:
    if existing_database_lock(binary) is not None:
        raise IdbCacheError(f"Active IDA database lock prevents warm cleanup: {binary}")
    for path in database_paths(binary):
        if path.exists():
            validate_plain_file(path, context="Warm worker database cleanup target")
            path.unlink()


def run_worker(
    *,
    identity_path: str | Path,
    workspace_root: str | Path,
    port_lock: str | Path,
    output_path: str | Path,
    memory_limit_mb: int,
) -> dict:
    identity = load_cache_identity(identity_path)
    root = Path(workspace_root).resolve()
    if not root.is_dir():
        raise IdbCacheError(f"Warm workspace is missing: {root}")
    _apply_memory_limit(memory_limit_mb)
    observed_runtime = None
    with exclusive_file_lock(port_lock):
        for record in identity["binaries"]:
            binary = root.joinpath(*Path(record["path"]).parts)
            validate_plain_file(binary, context="Warm worker binary")
            info = inspect_binary(binary)
            if (
                info.platform != record["platform"]
                or binary.stat().st_size != record["size"]
                or sha256_file(binary) != record["sha256"]
            ):
                raise IdbCacheError(f"Warm worker binary identity mismatch: {record['path']}")
            _cleanup_database(binary)
            ida_args = subprocess.list2cmdline(identity["normalized_ida_args"])
            try:
                with IdaMcpLifecycle(
                    binary,
                    record["platform"],
                    DEFAULT_HOST,
                    DEFAULT_PORT,
                    ida_args,
                    database_policy="rebuild",
                    save_on_success=True,
                ):
                    current_runtime = _observed_runtime(binary, identity["ida_runtime"])
                    if observed_runtime is None:
                        observed_runtime = current_runtime
                    elif observed_runtime != current_runtime:
                        raise IdbCacheError("Warm binaries observed inconsistent IDA runtime identities")
                validate_database_file_set(binary)
            except Exception:
                _cleanup_database(binary)
                raise
    if observed_runtime is None:
        raise IdbCacheError("Warm identity selected no binaries")
    write_canonical_json(output_path, observed_runtime)
    return observed_runtime


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Restricted neutral IDB warm worker")
    commands = parser.add_subparsers(dest="command", required=True)
    runtime = commands.add_parser("probe-runtime")
    runtime.add_argument("-ida-root", required=True)
    runtime.add_argument("-kernel-version", required=True)
    runtime.add_argument("-binary", required=True)
    runtime.add_argument("-plugin", action="append", default=[])
    runtime.add_argument("-output", required=True)
    run = commands.add_parser("run")
    run.add_argument("-identity", required=True)
    run.add_argument("-workspace-root", required=True)
    run.add_argument("-port-lock", required=True)
    run.add_argument("-output", required=True)
    run.add_argument("-memory-limit-mb", type=int, default=8192)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "probe-runtime":
            document = probe_runtime_contract(
                ida_root=args.ida_root,
                kernel_version=args.kernel_version,
                binary_path=args.binary,
                plugins=tuple(args.plugin),
            )
            write_canonical_json(args.output, document)
        else:
            run_worker(
                identity_path=args.identity,
                workspace_root=args.workspace_root,
                port_lock=args.port_lock,
                output_path=args.output,
                memory_limit_mb=args.memory_limit_mb,
            )
    except (IdbCacheError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
