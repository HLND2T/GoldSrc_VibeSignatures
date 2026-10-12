"""Label validated server movement functions; identities never locate addresses.

Linux names are the real 5.15 ELF symbols, correlated to 5.16 by current
call/argument evidence. Windows PlayStepSound is thiscall (the consumer uses a
fastcall adapter with an unused EDX); the PM callback is cdecl on both platforms.
"""

from pathlib import Path

import yaml

from ida_analyze_util import write_func_yaml

FUNCTION_IDENTITIES = {
    "CPlayerMove_PlayStepSound": {
        "windows": "CPlayerMove::PlayStepSound(int, float, bool)",
        "linux": "_ZN11CPlayerMove13PlayStepSoundEifb",
    },
    "CPlayerMove_PlaySoundFX": {
        "linux": "_ZN11CPlayerMove11PlaySoundFXEiPfiPcffii",
    },
    "PM_PlaySoundFX_SERVER": {
        "windows": "PM_PlaySoundFX_SERVER",
        "linux": "PM_PlaySoundFX_SERVER",
    },
}


def publish_player_move_identities(expected_outputs, platform):
    for output in expected_outputs:
        path = Path(output)
        symbol = path.name.removesuffix(f".{platform}.yaml")
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        payload["func_name"] = FUNCTION_IDENTITIES[symbol][platform]
        write_func_yaml(path, payload)
