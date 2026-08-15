"""DepotDownloader command helpers."""

from __future__ import annotations

import subprocess


def append_auth_args(command: list[str], username=None, password=None, remember_password=False) -> None:
    if username:
        command.extend(["-username", str(username)])
    if password:
        command.extend(["-password", str(password)])
    if remember_password:
        command.append("-remember-password")


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)
