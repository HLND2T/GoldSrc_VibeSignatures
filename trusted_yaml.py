"""Safe YAML helpers for repository configuration and generated artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SAFE_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_yaml(data) -> Any:
    return yaml.load(data, Loader=SAFE_LOADER)


def load_yaml_file(path: str | Path) -> Any:
    return load_yaml(Path(path).read_bytes())
