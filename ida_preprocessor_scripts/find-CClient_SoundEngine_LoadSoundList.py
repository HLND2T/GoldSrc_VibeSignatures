#!/usr/bin/env python3
"""Locate the Sven Co-op client CClient_SoundEngine::LoadSoundList body.

LoadSoundList parses the per-map sound-cache list and, inside its
"SENTENCELIST {" block, stops reading once the sentence table is full
(``if (m_iSentenceCount >= 2048) break;``) before handing each line to
ParseSentenceLine.  The exact block header literal is referenced by exactly
one function on every validated Sven client (8948/10257, Windows/Linux), and
that function always carries the sentence-count guard consumed by
find-CClient_SoundEngine_LoadSoundList-decompiles.

Windows keeps one full ``__thiscall`` body.  Both Linux builds split the
method: the public ``LoadSoundList()`` entry is a small guard wrapper
(loading flag + map time) that tail-jumps into the GCC
``LoadSoundList.part.N`` body with ``this`` in a register.  The literal owner
is that ``.part.N`` body (8948 ELF names it
``_ZN19CClient_SoundEngine13LoadSoundListEv.part.9``), which is the control-flow
root holding the parse loop; the artifact deliberately points at it, like
Mod_LoadModel.  Do not treat the Linux artifact as a hookable public entry.

The ParseSentenceLine diagnostics ("Sentence length too long! ...") are not
used here: on 8948 Linux ParseSentenceLine calls AddSentence through the PLT,
so the sentence-count access is not inside the diagnostic owner there.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAMES = ["CClient_SoundEngine_LoadSoundList"]
LITERAL = "SENTENCELIST {"


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
    _ = skill_name, old_yaml_map
    return await preprocess_string_owner_skill_with_pic_fallback(
        session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_name=TARGET_FUNCTION_NAMES[0],
        literal=LITERAL,
        debug=debug,
    )
