"""Pure LLM spec normalization shared by runtime and static declaration validation."""

import re
from collections.abc import Mapping

from scalar_artifact import validate_scalar_artifact

LLM_RESULT_SECTIONS = frozenset(
    {"found_vcall", "found_call", "found_funcptr", "found_gv", "found_struct_offset", "found_scalar"}
)
LLM_SPEC_REQUIRED_KEYS = frozenset(
    {
        "symbol_name",
        "prompt_path",
        "reference_yaml_paths",
        "expected_result_sections",
        "dependency_policy",
    }
)
LLM_SPEC_OPTIONAL_KEYS = frozenset({"instruction_rules", "expected_size", "expected_value"})


def normalize_llm_decompile_specs(specs):
    normalized = {}
    for raw_spec in specs or ():
        if not isinstance(raw_spec, Mapping):
            return None
        keys = set(raw_spec)
        if not LLM_SPEC_REQUIRED_KEYS <= keys or keys - (LLM_SPEC_REQUIRED_KEYS | LLM_SPEC_OPTIONAL_KEYS):
            return None
        symbol_name = raw_spec.get("symbol_name")
        prompt_path = raw_spec.get("prompt_path")
        references = raw_spec.get("reference_yaml_paths")
        sections = raw_spec.get("expected_result_sections")
        policy = raw_spec.get("dependency_policy")
        if (
            not isinstance(symbol_name, str)
            or not symbol_name
            or symbol_name in normalized
            or not isinstance(prompt_path, str)
            or not prompt_path
            or not isinstance(references, (tuple, list))
            or not references
            or any(not isinstance(value, str) or not value for value in references)
            or not isinstance(sections, (tuple, list, set))
            or not sections
            or any(value not in LLM_RESULT_SECTIONS for value in sections)
            or not isinstance(policy, Mapping)
            or not policy
        ):
            return None
        if any(
            not isinstance(name, str) or not name or not isinstance(value, str) or value not in {"required", "optional"}
            for name, value in policy.items()
        ):
            return None
        policy_keys = [name.casefold() for name in policy]
        if len(set(policy_keys)) != len(policy_keys):
            return None
        spec = {
            "symbol_name": symbol_name,
            "prompt_path": prompt_path,
            "reference_yaml_paths": list(dict.fromkeys(references)),
            "expected_result_sections": list(dict.fromkeys(sections)),
            "dependency_policy": dict(policy),
        }
        rules = raw_spec.get("instruction_rules")
        if rules is not None:
            if not isinstance(rules, (tuple, list)) or not rules:
                return None
            normalized_rules = []
            for rule in rules:
                if not isinstance(rule, Mapping) or set(rule) != {"regex", "text"}:
                    return None
                regex = rule.get("regex")
                text = rule.get("text")
                if not isinstance(regex, str) or not regex or not isinstance(text, str) or not text:
                    return None
                try:
                    re.compile(regex)
                except re.error:
                    return None
                normalized_rules.append({"regex": regex, "text": text})
            spec["instruction_rules"] = normalized_rules
        expected_size = raw_spec.get("expected_size")
        if expected_size is not None:
            if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size <= 0:
                return None
            spec["expected_size"] = expected_size
        if "expected_value" in raw_spec:
            try:
                validate_scalar_artifact({"scalar_name": symbol_name, "scalar_value": raw_spec["expected_value"]})
            except ValueError:
                return None
            spec["expected_value"] = raw_spec["expected_value"]
        normalized[symbol_name] = spec
    return normalized


def select_llm_specs(declaration, *, branch=None, symbols=None, expected_values=None, instruction_rules=None):
    """Copy a static selection and supply only audited non-dependency runtime fields."""
    from copy import deepcopy

    specs = deepcopy(declaration[branch] if branch is not None else declaration)
    if symbols is not None:
        by_symbol = {spec["symbol_name"]: spec for spec in specs}
        specs = [by_symbol[symbol] for symbol in symbols]
    for spec in specs:
        name = spec["symbol_name"]
        if expected_values is not None and name in expected_values:
            spec["expected_value"] = expected_values[name]
        if instruction_rules is not None and name in instruction_rules:
            spec["instruction_rules"] = instruction_rules[name]
    return specs
