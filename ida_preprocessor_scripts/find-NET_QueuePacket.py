"""Locate the packet receiver through its own oversize-packet diagnostic.

Classic HL/CoF name NET_QueuePacket in the diagnostic; Sven's socket layer
uses a shorter message. Both are owned by the receiver, not NET_GetPacket.
The Windows cdecl int(int netsrc) result is false when no packet was queued.
ThreadGuard uses that contract to drain the thread loop during shutdown.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    literal = (
        "%s sent oversize packet\n"
        if Path(new_binary_dir).parent.name.startswith("svencoop-")
        else "NET_QueuePacket:  Oversize packet from %s\n"
    )
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["NET_QueuePacket"],
        func_xrefs=[{"func_name": "NET_QueuePacket", "xref_strings": ["FULLMATCH:" + literal]}],
        generate_yaml_desired_fields=[
            ("NET_QueuePacket", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
        ],
        debug=debug,
    )
