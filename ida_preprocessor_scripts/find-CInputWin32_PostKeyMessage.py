#!/usr/bin/env python3
"""Locate the private CInputWin32::PostKeyMessage(KeyValues*) in vgui2.

vgui2/src/InputWin32.cpp has exactly four callers, each building one message:
InternalKeyCodePressed/Typed, InternalKeyTyped and InternalKeyCodeReleased pass
``new KeyValues("<literal>", ...)`` to PostKeyMessage, which either posts it to
the key focus through ``ivgui()->PostMessage(focus, message, NULL)`` or calls
``message->deleteThis()``.

MSVC keeps the call: all four literal owners must forward their constructed
message, as the only stack argument of a ``this`` call, to one ``ret 4`` callee.
GCC inlines PostKeyMessage into all four callers while keeping the unreferenced
out-of-line body. The callers fix the current PostMessage/deleteThis slots, then
exactly one other g_pIVgui user must post-or-delete its own message parameter
through those slots. ELF symbols are not used for discovery.
"""

from ida_preprocessor_scripts._vgui_paint_common import walk, write_function


TARGET = "CInputWin32_PostKeyMessage"
FUNC_NAME = "CInputWin32::PostKeyMessage(KeyValues*)"

LOCATE = r"""
platform=values['platform']
literals=values['literals']
message_index=values['message_index']
parameter=('arg',1)

def literal_references(text):
    # Raw NUL-delimited scan keeps FULLMATCH semantics without rebuilding the
    # IDB-wide string list that later skills enumerate.
    needle=text.encode('ascii')+b'\x00'
    found=set()
    for segment_start in idautils.Segments():
        segment=ida_segment.getseg(int(segment_start))
        if segment is None or not int(getattr(segment,'perm',0))&ida_segment.SEGPERM_READ:
            continue
        data=ida_bytes.get_bytes(int(segment.start_ea),int(segment.end_ea-segment.start_ea)) or b''
        offset=data.find(needle)
        while offset!=-1:
            if offset==0 or data[offset-1]==0:
                literal=int(segment.start_ea)+offset
                for ref in idautils.DataRefsTo(literal):
                    function=ida_funcs.get_func(int(ref))
                    if function is not None and ida_bytes.is_code(ida_bytes.get_flags(int(ref))):
                        found.add((literal,int(function.start_ea)))
            offset=data.find(needle,offset+1)
    if len(found)!=1:
        raise ValueError('literal owner is not unique: '+text)
    return next(iter(found))

def global_receiver(value):
    return value is not None and value[0]=='load' and value[2]==0 and value[1] is not None and value[1][0]=='const'

def post_or_delete(flow, message):
    posts=set()
    deletes=set()
    for call in flow['calls']:
        targets=virtual_targets(call['target'])
        if len(targets)!=1:
            continue
        receiver,slot=targets[0]
        arguments=call['args']
        if (len(arguments)>message_index and arguments[0]==receiver and global_receiver(receiver)
                and message in alternatives(arguments[message_index])):
            posts.add((receiver,slot))
        if receiver==message and arguments and arguments[0]==message:
            deletes.add(slot)
    return posts,deletes

def constructed_message(flow, literal):
    # KeyValues(name, firstKey, firstValue): MSVC returns the thiscall object,
    # GCC passes it as the first cdecl argument.
    messages=set()
    for call in flow['calls']:
        if call['direct'] is None:
            continue
        if platform=='windows':
            if call['stack_args'][:1]==[('const',literal)] and call['this'] is not None:
                messages.add(('result',call['ea']))
        elif call['stack_args'][1:2]==[('const',literal)] and call['stack_args'][0] is not None:
            messages.add(call['stack_args'][0])
    if len(messages)!=1:
        raise ValueError('KeyValues construction is ambiguous')
    return next(iter(messages))

def stack_purge(target):
    try:
        return callee_stack_purge(target)
    except ValueError:
        return None

owners={}
for text in literals:
    literal,owner=literal_references(text)
    flow=flow_at(owner,platform)
    owners[owner]=(flow,constructed_message(flow,literal))
if len(owners)!=len(literals):
    raise ValueError('key-message literal owners are not distinct')

if platform=='windows':
    targets=set()
    for owner,(flow,message) in owners.items():
        forwarded=set()
        for call in flow['calls']:
            choices=set(alternatives(call['stack_args'][0])) if call['stack_args'] else set()
            # A failed allocation yields the NULL alternative of new KeyValues.
            if (call['direct'] and call['this']==('arg',0) and message in choices
                    and choices<={message,('const',0)} and stack_purge(call['direct'])==4):
                forwarded.add(call['direct'])
        if len(forwarded)!=1:
            raise ValueError('key message is not forwarded through one thiscall')
        targets|=forwarded
    if len(targets)!=1:
        raise ValueError('key-message owners disagree on PostKeyMessage')
    target=next(iter(targets))
    posts,deletes=post_or_delete(flow_at(target,platform),parameter)
    if len(posts)!=1 or len(deletes)!=1:
        raise ValueError('PostKeyMessage does not post or delete its message')
else:
    shapes=set()
    for flow,message in owners.values():
        posts,deletes=post_or_delete(flow,message)
        if len(posts)!=1 or len(deletes)!=1:
            raise ValueError('inlined PostKeyMessage dispatch is ambiguous')
        shapes.add((next(iter(posts)),next(iter(deletes))))
    if len(shapes)!=1:
        raise ValueError('inlined PostKeyMessage dispatch disagrees')
    post,delete=next(iter(shapes))
    interface=post[0][1][1]
    references=set(idautils.DataRefsTo(interface))
    for segment_start in idautils.Segments():
        if not is_got(segment_start):
            continue
        segment=ida_segment.getseg(int(segment_start))
        for slot in range(int(segment.start_ea),int(segment.end_ea),4):
            if int(ida_bytes.get_dword(slot))==interface:
                references|=set(idautils.DataRefsTo(slot))
    users=set()
    for ref in references:
        function=ida_funcs.get_func(int(ref))
        if function is not None and ida_bytes.is_code(ida_bytes.get_flags(int(ref))):
            users.add(int(function.start_ea))
    candidates=[]
    for start in sorted(users-set(owners)):
        posts,deletes=post_or_delete(flow_at(start,platform),parameter)
        if posts=={post} and deletes=={delete}:
            candidates.append(start)
    if len(candidates)!=1:
        raise ValueError('out-of-line PostKeyMessage body is not unique')
    target=candidates[0]
result={'target':target}
"""

KEY_MESSAGE_LITERALS = ("KeyCodePressed", "KeyCodeTyped", "KeyTyped", "KeyCodeReleased")
# IVGui::PostMessage(VPANEL target, KeyValues *message, VPANEL from, float delay):
# the receiver occupies argument 0 in both the thiscall and cdecl call models.
POST_MESSAGE_ARGUMENT_INDEX = 2


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    found = await walk(
        session,
        LOCATE,
        dict(
            platform=platform,
            literals=list(KEY_MESSAGE_LITERALS),
            message_index=POST_MESSAGE_ARGUMENT_INDEX,
        ),
    )
    if found.get("error") or not isinstance(found.get("target"), int):
        if debug:
            print(f"    Preprocess: {TARGET}: {found}")
        return False
    return await write_function(session, expected_outputs, TARGET, FUNC_NAME, found["target"], image_base)
