"""A finder-owned template exposed through the common file-based prompt API.

The source planner conservatively treats the shared prompt directory as a
dependency of every LLM finder. Keeping this specialized template in an imported
module makes its ownership precise without changing the shared planner contract.
"""

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

SCOREINFO_PROMPT = """Identify the array base of "{symbol_name_list}" in the current ScoreInfo message handler.

Annotated reference:

{reference_blocks}

Current target:

{target_blocks}

Return exactly ONE found_gv entry: the 16-bit store of frags at array member offset zero.
The handler reads a player index with READ_BYTE, followed by four READ_SHORT calls for
frags, deaths, playerclass, and teamnumber. Follow the FIRST READ_SHORT result through
register copies to its indexed array store. Check the player-index data flow as well.
Compiler registers, addresses, and store ordering can differ from the reference.

The reference's frags member is at offset zero. Reject deaths, playerclass, teamnumber,
comparisons, loads, and interior-address arithmetic. Do not collect every array access.
Do not include any other found_gv entries even when they belong to the same array.
Do not copy reference addresses, registers, or anonymous IDA names into target results.

Return only a YAML mapping with the keys found_vcall, found_call, found_funcptr,
found_gv, and found_struct_offset. All lists except found_gv must be empty.
The found_gv entry must contain insn_va, insn_disasm, and gv_name. Use the exact current
target instruction text and address, and the requested canonical symbol as gv_name.
If the target evidence cannot identify one zero-offset frags store, return all five lists empty.
"""


@contextmanager
def scoreinfo_prompt_path():
    with TemporaryDirectory(prefix="gsvibe-scoreinfo-prompt-") as directory:
        path = Path(directory) / "scoreinfo.md"
        path.write_text(SCOREINFO_PROMPT, encoding="utf-8")
        yield str(path)
