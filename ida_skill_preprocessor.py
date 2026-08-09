"""Load deterministic and LLM preprocessors by safe skill name."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

SAFE_SKILL_RE = re.compile(r"^[A-Za-z0-9_.-]+$", re.ASCII)


class PreprocessorError(RuntimeError):
    pass


def _load_preprocessor(root: str | Path, skill_name: str, function_name: str):
    if not SAFE_SKILL_RE.fullmatch(str(skill_name)):
        raise PreprocessorError(f"Unsafe skill name: {skill_name!r}")
    root = Path(root).resolve()
    path = (root / f"{skill_name}.py").resolve()
    if path.parent != root:
        raise PreprocessorError(f"Preprocessor path escapes root: {path}")
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(f"vibesignatures_preprocessor_{skill_name}", path)
    if spec is None or spec.loader is None:
        raise PreprocessorError(f"Unable to load preprocessor: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise PreprocessorError(f"Failed to import preprocessor {path}: {exc}") from exc
    function = getattr(module, function_name, None)
    if not callable(function):
        raise PreprocessorError(f"Preprocessor {path} has no callable {function_name}")
    return function


def preprocess_skill(skill_name: str, *, context: dict, scripts_dir: str | Path = "ida_preprocessor_scripts") -> bool:
    function = _load_preprocessor(scripts_dir, skill_name, "preprocess_skill")
    return bool(function(context=context)) if function else False


def preprocess_skill_with_llm(
    skill_name: str,
    *,
    context: dict,
    llm_config: dict | None = None,
    scripts_dir: str | Path = "ida_llm_preprocessor_scripts",
) -> bool:
    function = _load_preprocessor(scripts_dir, skill_name, "preprocess_skill_with_llm")
    if function is None:
        return False
    llm_context = dict(context)
    llm_context["llm_config"] = dict(llm_config or {})
    return bool(function(context=llm_context))
