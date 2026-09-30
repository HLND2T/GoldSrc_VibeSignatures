"""Instruction selection for the SvEngine filter setters' PIC global accesses."""


def filter_global_specs(specs, platform):
    if platform != "linux":
        return specs
    # The final [eax]/[edx] store has no encoded address. IDA may attach a
    # misleading GOT-base xref to it. Select the earlier GOT pointer load
    # (8948) or local-address LEA (10257), whose displacement the runtime
    # global resolver can actually decode.
    return [
        {
            **spec,
            "instruction_rules": [
                {
                    "regex": (
                        r"(?i)^(?:mov|lea)\s+e(?:ax|bx|cx|dx|si|di|bp),\s+(?:ds:)?"
                        r"(?:\([^,\[\]]+\s-\s[^,\[\]]+\)\[(?:eax|ebx)\]"
                        r"|\[(?:eax|ebx)[+-][^,\[\]]+\])"
                    ),
                    "text": (
                        "Select the GOT pointer load or object-address LEA into a general register. "
                        "Trace that pointer to the corresponding parameter store. Do not select "
                        "the final indirect store, a stack argument load, or the get-PC thunk."
                    ),
                }
            ],
        }
        for spec in specs
    ]


def filter_global_rules(names, platform):
    """Return only runtime instruction rules; dependency declarations stay in callers."""
    if platform != "linux":
        return None
    return {
        spec["symbol_name"]: spec["instruction_rules"]
        for spec in filter_global_specs([{"symbol_name": name} for name in names], platform)
    }
