"""Run the portal render-state proofs against current IDB instructions."""

import inspect

from ida_preprocessor_scripts import _portal_render_state
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk

BODY = r"""
original_decode = decode_function
def decode_function(ea):
    instructions = original_decode(ea)
    for item in instructions:
        refs = list(idautils.DataRefsFrom(item['ea']))
        if len(refs) == 1:
            for op in item['operands']:
                if op['kind'] == 'unsupported' or (op['kind'] == 'mem' and op['base'] not in {'esp', 'ebp'}):
                    op.update(kind='global', value=int(refs[0]))
    return instructions

functions = {}
frontier = [values['draw' if values['mode'] == 'shader' else 'render']]
for depth in range(3):
    following = set()
    for ea in frontier:
        functions[ea] = decode_function(ea)
        if depth < 2:
            following.update(callees(ea))
    frontier = sorted(following - functions.keys())
if values['mode'] == 'shader':
    result = recover_shader_member(values['init'], values['draw'], functions, values['platform'])
else:
    candidates = [ea for ea, body in functions.items() if clip_setup(body, values['platform'])
                  and any(clip_call_arguments(caller, ea, values['platform']) for caller in functions.values())]
    if len(candidates) != 1:
        raise ValueError('clip setup candidates missing or ambiguous: %r' % candidates)
    result = {'function': candidates[0]}
"""


async def run_render_state_walk(session, values):
    source = inspect.getsource(_portal_render_state).replace(
        "from ida_preprocessor_scripts._portal_layout import Trace, pointer, _dominates", ""
    )
    return await run_layout_walk(session, values, source + "\n" + BODY)
