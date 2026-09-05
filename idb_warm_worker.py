#!/usr/bin/env python3
"""Warm one GoldSrc IDA database with bare idalib and no MCP server."""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
from pathlib import Path

from binary_format import inspect_binary
from ida_database_paths import IdaDatabasePathError, existing_database_lock, validate_plain_file

DEFAULT_MEMORY_LIMIT_MIB = 8192
_WINDOWS_JOB_HANDLE = None


def _apply_memory_limit(limit_mb: int) -> None:
    if limit_mb < 256:
        raise IdaDatabasePathError("Warm worker memory limit must be at least 256 MiB")
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
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise IdaDatabasePathError(f"Unable to create warm worker Job Object: {ctypes.get_last_error()}")
    try:
        information = ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000 | 0x00000200
        information.JobMemoryLimit = limit_bytes
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(information), ctypes.sizeof(information)):
            raise IdaDatabasePathError(f"Unable to set warm worker Job Object limit: {ctypes.get_last_error()}")
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            raise IdaDatabasePathError(f"Unable to assign warm worker Job Object: {ctypes.get_last_error()}")
    except Exception:
        kernel32.CloseHandle(job)
        raise
    global _WINDOWS_JOB_HANDLE
    _WINDOWS_JOB_HANDLE = job


def _load_ida_modules():
    """Initialize idalib first, then load the APIs used by database warming."""
    import idapro
    import ida_auto
    import ida_loader

    return idapro, ida_auto, ida_loader


def _load_ida_version_modules():
    """Initialize idalib first, then load the kernel-version API."""
    import idapro
    import idaapi

    return idapro, idaapi


def ida_kernel_version() -> str:
    _idapro, idaapi = _load_ida_version_modules()
    version = str(idaapi.get_kernel_version()).strip()
    if not version:
        raise IdaDatabasePathError("IDA kernel version probe returned an empty value")
    return version


def warm_binary(
    binary_path: str | os.PathLike[str],
    *,
    memory_limit_mb: int | None = DEFAULT_MEMORY_LIMIT_MIB,
) -> None:
    """Open, auto-analyze, save, and close exactly one validated binary."""
    binary = validate_plain_file(Path(binary_path).resolve(strict=True), context="Warm worker binary")
    inspect_binary(binary)
    lock = existing_database_lock(binary)
    if lock is not None:
        raise IdaDatabasePathError(f"Active IDA database lock prevents warm startup: {lock}")
    if memory_limit_mb is not None:
        _apply_memory_limit(memory_limit_mb)

    idapro, ida_auto, ida_loader = _load_ida_modules()
    if idapro.open_database(str(binary), run_auto_analysis=True) != 0:
        raise IdaDatabasePathError(f"Unable to open warm database: {binary}")
    try:
        if not ida_auto.auto_wait():
            raise IdaDatabasePathError(f"Warm auto-analysis did not complete: {binary}")
        if not ida_loader.save_database(None, 0):
            raise IdaDatabasePathError(f"Unable to save warm database: {binary}")
    except Exception as warm_error:
        try:
            idapro.close_database()
        except Exception as close_error:
            raise warm_error from close_error
        raise
    else:
        idapro.close_database()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-ida-version", action="store_true")
    commands = parser.add_subparsers(dest="command")
    run = commands.add_parser("run")
    run.add_argument("-binary", required=True)
    memory = run.add_mutually_exclusive_group()
    memory.add_argument("-memory-limit-mib", type=int, default=DEFAULT_MEMORY_LIMIT_MIB)
    memory.add_argument("--disable-memory-limit", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.print_ida_version:
            if args.command is not None:
                parser.error("--print-ida-version cannot be combined with run")
            print(ida_kernel_version())
        elif args.command == "run":
            warm_binary(
                args.binary,
                memory_limit_mb=None if args.disable_memory_limit else args.memory_limit_mib,
            )
        else:
            parser.error("run is required unless --print-ida-version is used")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
