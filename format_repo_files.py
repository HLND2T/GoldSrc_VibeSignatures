"""Format or check repository Python and YAML files."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def repository_format_files() -> tuple[list[str], list[str]]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git ls-files failed")
    paths = [path for path in result.stdout.splitlines() if Path(path).is_file()]
    python_files = sorted(path for path in paths if path.endswith(".py"))
    yaml_files = sorted(
        path
        for path in paths
        if path.endswith((".yaml", ".yml")) and not path.replace("\\", "/").startswith("gamesymbols/")
    )
    return python_files, yaml_files


def _run(command: list[str], paths: list[str]) -> int:
    if not paths:
        return 0
    return subprocess.run([*command, *paths], check=False).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Format Python with Ruff and YAML with yamlfix")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        python_files, yaml_files = repository_format_files()
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1
    ruff = ["ruff", "format"] + (["--check"] if args.check else [])
    yamlfix = ["yamlfix"] + (["--check"] if args.check else [])
    results = (_run(ruff, python_files), _run(yamlfix, yaml_files))
    return 1 if any(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
