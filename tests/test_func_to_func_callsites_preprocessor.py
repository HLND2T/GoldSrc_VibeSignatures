import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts._func_to_func_callsites_common import (
    LOCATE_PY,
    expected_callsite_outputs,
    preprocess_func_to_func_callsites,
)

ROOT = Path(__file__).parents[1]
SOUND_SCRIPT = ROOT / "ida_preprocessor_scripts" / "find-S_LoadSound_to_FS_Open_callsites.py"
MODEL_SCRIPT = ROOT / "ida_preprocessor_scripts" / "find-Mod_LoadModel_to_FS_Open_callsites.py"


def _load_script(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FuncToFuncCallsiteHelperTests(unittest.IsolatedAsyncioTestCase):
    def test_locator_snippet_compiles_after_address_substitution(self):
        code = LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", "0x101ff610").replace("CALLEE_EA_PLACEHOLDER", "0x101c8010")
        compile(code, str(SOUND_SCRIPT), "exec")

    def test_finder_wrappers_load(self):
        sound = _load_script(SOUND_SCRIPT, "find_s_loadsound_callsites_under_test")
        model = _load_script(MODEL_SCRIPT, "find_mod_loadmodel_callsites_under_test")
        self.assertEqual("S_LoadSound_to_FS_Open_callsite_", sound.PATCH_NAME_PREFIX)
        self.assertEqual("Mod_LoadModel_to_FS_Open_callsite_", model.PATCH_NAME_PREFIX)

    def test_expected_outputs_must_be_contiguous_indexes(self):
        prefix = "S_LoadSound_to_FS_Open_callsite_"
        self.assertIsNone(expected_callsite_outputs([], prefix))
        self.assertIsNone(expected_callsite_outputs([Path(f"{prefix}1.windows.yaml")], prefix))
        parsed = expected_callsite_outputs(
            [
                Path(f"{prefix}1.windows.yaml"),
                Path(f"{prefix}0.windows.yaml"),
            ],
            prefix,
        )
        self.assertEqual(
            [
                "S_LoadSound_to_FS_Open_callsite_0",
                "S_LoadSound_to_FS_Open_callsite_1",
            ],
            [name for name, _path in parsed],
        )

    async def test_requires_both_function_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            (binary_dir / "S_LoadSound.windows.yaml").write_text(
                "func_name: S_LoadSound\nfunc_va: '0x101ff610'\n",
                encoding="utf-8",
            )

            result = await preprocess_func_to_func_callsites(
                session=None,
                skill_name="find-S_LoadSound_to_FS_Open_callsites",
                expected_outputs=[binary_dir / "S_LoadSound_to_FS_Open_callsite_0.windows.yaml"],
                new_binary_dir=binary_dir,
                platform="windows",
                image_base=0x10000000,
                patch_name_prefix="S_LoadSound_to_FS_Open_callsite_",
                owner_func_name="S_LoadSound",
                callee_func_name="FS_Open",
            )

        self.assertIs(result, False)

    async def test_writes_address_ordered_callsite_without_patch_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            output = binary_dir / "S_LoadSound_to_FS_Open_callsite_0.windows.yaml"
            (binary_dir / "S_LoadSound.windows.yaml").write_text(
                "func_name: S_LoadSound\nfunc_va: '0x101ff610'\n",
                encoding="utf-8",
            )
            (binary_dir / "FS_Open.windows.yaml").write_text(
                "func_name: FS_Open\nfunc_va: '0x101c8010'\n",
                encoding="utf-8",
            )
            inspect = AsyncMock(
                return_value={
                    "func_va": "0x101ff610",
                    "func_rva": "0x1ff610",
                    "func_size": "0x538",
                    "func_sig": "55 8B EC",
                }
            )
            locate = AsyncMock(
                return_value={
                    "pointer_size": 4,
                    "sites": [
                        {
                            "ea": "0x101ff74c",
                            "mnem": "call",
                            "disasm": "call FS_Open",
                            "insn_len": 5,
                            "patch_sig": "E8 AA BB CC DD 83 C4 08",
                            "patch_sig_disp": 0,
                        }
                    ],
                }
            )
            find_unique = AsyncMock(return_value=0x101FF74C)

            with (
                patch(
                    "ida_preprocessor_scripts._func_to_func_callsites_common._inspect_function_via_mcp",
                    inspect,
                ),
                patch(
                    "ida_preprocessor_scripts._func_to_func_callsites_common.locate_callsites",
                    locate,
                ),
                patch(
                    "ida_preprocessor_scripts._func_to_func_callsites_common._find_unique_bytes",
                    find_unique,
                ),
                patch("ida_preprocessor_scripts._func_to_func_callsites_common.write_patch_yaml") as write_patch_yaml,
            ):
                result = await preprocess_func_to_func_callsites(
                    session="session",
                    skill_name="find-S_LoadSound_to_FS_Open_callsites",
                    expected_outputs=[output],
                    new_binary_dir=binary_dir,
                    platform="windows",
                    image_base=0x10000000,
                    patch_name_prefix="S_LoadSound_to_FS_Open_callsite_",
                    owner_func_name="S_LoadSound",
                    callee_func_name="FS_Open",
                )

        self.assertIs(result, True)
        inspect.assert_awaited_once_with(
            "session",
            0x101FF610,
            0x10000000,
            "S_LoadSound",
            allow_across_function_boundary=False,
        )
        locate.assert_awaited_once_with("session", 0x101FF610, 0x101C8010)
        find_unique.assert_awaited_once_with("session", "E8 AA BB CC DD 83 C4 08")
        write_patch_yaml.assert_called_once_with(
            output,
            {
                "patch_name": "S_LoadSound_to_FS_Open_callsite_0",
                "patch_va": hex(0x101FF74C),
                "patch_rva": hex(0x1FF74C),
                "patch_sig": "E8 AA BB CC DD 83 C4 08",
                "patch_sig_disp": 0,
            },
        )
        self.assertNotIn("patch_bytes", write_patch_yaml.call_args.args[1])

    async def test_fails_when_found_count_does_not_match_expected(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            (binary_dir / "Mod_LoadModel.windows.yaml").write_text(
                "func_name: Mod_LoadModel\nfunc_va: '0x10240290'\n",
                encoding="utf-8",
            )
            (binary_dir / "FS_Open.windows.yaml").write_text(
                "func_name: FS_Open\nfunc_va: '0x101c8010'\n",
                encoding="utf-8",
            )
            inspect = AsyncMock(
                return_value={
                    "func_va": "0x10240290",
                    "func_sig": "55 8B EC",
                }
            )
            locate = AsyncMock(
                return_value={
                    "pointer_size": 4,
                    "sites": [
                        {
                            "ea": "0x10240328",
                            "insn_len": 5,
                            "patch_sig": "E8 AA BB CC DD",
                            "patch_sig_disp": 0,
                        },
                        {
                            "ea": "0x10240340",
                            "insn_len": 5,
                            "patch_sig": "E9 AA BB CC DD",
                            "patch_sig_disp": 0,
                        },
                    ],
                }
            )

            with (
                patch(
                    "ida_preprocessor_scripts._func_to_func_callsites_common._inspect_function_via_mcp",
                    inspect,
                ),
                patch(
                    "ida_preprocessor_scripts._func_to_func_callsites_common.locate_callsites",
                    locate,
                ),
                patch("ida_preprocessor_scripts._func_to_func_callsites_common.write_patch_yaml") as write_patch_yaml,
            ):
                result = await preprocess_func_to_func_callsites(
                    session="session",
                    skill_name="find-Mod_LoadModel_to_FS_Open_callsites",
                    expected_outputs=[binary_dir / "Mod_LoadModel_to_FS_Open_callsite_0.windows.yaml"],
                    new_binary_dir=binary_dir,
                    platform="windows",
                    image_base=0x10000000,
                    patch_name_prefix="Mod_LoadModel_to_FS_Open_callsite_",
                    owner_func_name="Mod_LoadModel",
                    callee_func_name="FS_Open",
                )

        self.assertIs(result, False)
        write_patch_yaml.assert_not_called()


if __name__ == "__main__":
    unittest.main()
