"""Format or check repository Python and YAML files."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

EXCLUDED_FORMAT_PREFIXES = (".claude/", ".codex/")
# Windows CreateProcess accepts at most 32767 UTF-16 units, including the NUL.
# Leave headroom and use the same bounded batches on every platform.
MAX_COMMAND_LINE_UNITS = 30000


def _is_excluded_format_path(path: str) -> bool:
    normalized_path = path.replace("\\", "/").casefold()
    return normalized_path.startswith(EXCLUDED_FORMAT_PREFIXES)


def repository_format_files() -> tuple[list[str], list[str]]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git ls-files failed")
    paths = [path for path in result.stdout.splitlines() if Path(path).is_file() and not _is_excluded_format_path(path)]
    python_files = sorted(path for path in paths if path.endswith(".py"))
    yaml_files = sorted(
        path
        for path in paths
        if path.endswith((".yaml", ".yml"))
        and not path.replace("\\", "/").startswith("bin_artifacts/")
        and not path.replace("\\", "/").startswith("gamesymbols/")
        and not path.replace("\\", "/").startswith("ida_preprocessor_scripts/references/")
    )
    return python_files, yaml_files


def _path_batches(command: list[str], paths: list[str]):
    prefix_units = len(subprocess.list2cmdline(command).encode("utf-16-le")) // 2 + 1
    batch = []
    batch_units = prefix_units
    for path in paths:
        # Serialize each argument exactly as Popen does on Windows; include its
        # separator, quotes, escaped backslashes and non-BMP UTF-16 characters.
        path_units = len(subprocess.list2cmdline([path]).encode("utf-16-le")) // 2 + 1
        if prefix_units + path_units > MAX_COMMAND_LINE_UNITS:
            raise RuntimeError(f"Formatter argument exceeds command-line budget: {path}")
        if batch and batch_units + path_units > MAX_COMMAND_LINE_UNITS:
            yield batch
            batch = []
            batch_units = prefix_units
        batch.append(path)
        batch_units += path_units
    if batch:
        yield batch


def _run(command: list[str], paths: list[str]) -> int:
    exit_code = 0
    for batch in _path_batches(command, paths):
        result = subprocess.run([*command, *batch], check=False).returncode
        if result and not exit_code:
            exit_code = result
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(description="Format Python with Ruff and YAML with yamlfix")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        python_files, yaml_files = repository_format_files()
        ruff = ["ruff", "format"] + (["--check"] if args.check else [])
        yamlfix = ["yamlfix"] + (["--check"] if args.check else [])
        results = (_run(ruff, python_files), _run(yamlfix, yaml_files))
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1
    return 1 if any(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
