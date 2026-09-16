"""Locate the Windows group loader to exclude its inlined sprite-frame body.

HL25 reports an invalid group interval with Mod_LoadSpriteGroup: interval<=0;
SvEngine uses a sprite-name diagnostic instead. Each selected literal has one
owner on the validated HL10210 / Sven8948 / Sven10257 Windows inputs. This is
a predecessor artifact, not an extra downstream global or call-site output.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill

NAME = "Mod_LoadSpriteGroup"
HL_INTERVAL_ERROR = "Mod_LoadSpriteGroup: interval<=0"
SVEN_INTERVAL_ERROR = 'Sprite "%s" has frame group with interval <= 0'


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    del skill_name, old_yaml_map
    if platform != "windows" or new_binary_dir is None:
        return False
    gamever = Path(new_binary_dir).parent.name
    literal = SVEN_INTERVAL_ERROR if gamever.startswith("svencoop-") else HL_INTERVAL_ERROR
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[NAME],
        func_xrefs=[{"func_name": NAME, "xref_strings": ["FULLMATCH:" + literal]}],
        generate_yaml_desired_fields=[(NAME, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])],
        debug=debug,
    )
