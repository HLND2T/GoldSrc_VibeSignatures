import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from ida_analyze_util import preprocess_patch_via_mcp


ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "ida_preprocessor_scripts" / "find-Cvar_Set_to_Cvar_DirectSet_callsites.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("find_cvar_set_callsites_under_test", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CvarSetCallsitePreprocessorTests(unittest.IsolatedAsyncioTestCase):
    def test_locator_snippet_compiles_after_address_substitution(self):
        script = _load_script()
        code = script.LOCATE_PY.replace("CVAR_SET_EA_PLACEHOLDER", "0x101be0b0").replace(
            "CVAR_DIRECTSET_EA_PLACEHOLDER", "0x101bdb80"
        )

        compile(code, str(SCRIPT_PATH), "exec")

    def test_expected_outputs_must_be_contiguous_indexes(self):
        script = _load_script()
        self.assertIsNone(script._expected_callsite_outputs([]))
        self.assertIsNone(
            script._expected_callsite_outputs([Path("Cvar_Set_to_Cvar_DirectSet_callsite_1.windows.yaml")])
        )
        parsed = script._expected_callsite_outputs(
            [
                Path("Cvar_Set_to_Cvar_DirectSet_callsite_1.windows.yaml"),
                Path("Cvar_Set_to_Cvar_DirectSet_callsite_0.windows.yaml"),
            ]
        )
        self.assertEqual(
            [
                "Cvar_Set_to_Cvar_DirectSet_callsite_0",
                "Cvar_Set_to_Cvar_DirectSet_callsite_1",
            ],
            [name for name, _path in parsed],
        )

    async def test_requires_both_function_artifacts(self):
        script = _load_script()
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            (binary_dir / "Cvar_Set.windows.yaml").write_text(
                "func_name: Cvar_Set\nfunc_va: '0x101be0b0'\n",
                encoding="utf-8",
            )

            result = await script.preprocess_skill(
                session=None,
                skill_name="find-Cvar_Set_to_Cvar_DirectSet_callsites",
                expected_outputs=[binary_dir / "Cvar_Set_to_Cvar_DirectSet_callsite_0.windows.yaml"],
                old_yaml_map=None,
                new_binary_dir=binary_dir,
                platform="windows",
                image_base=0x10000000,
            )

        self.assertIs(result, False)

    async def test_writes_address_ordered_callsite_without_patch_bytes(self):
        script = _load_script()
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            output = binary_dir / "Cvar_Set_to_Cvar_DirectSet_callsite_0.windows.yaml"
            (binary_dir / "Cvar_Set.windows.yaml").write_text(
                "func_name: Cvar_Set\nfunc_va: '0x101be0b0'\n",
                encoding="utf-8",
            )
            (binary_dir / "Cvar_DirectSet.windows.yaml").write_text(
                "func_name: Cvar_DirectSet\nfunc_va: '0x101bdb80'\n",
                encoding="utf-8",
            )
            inspect = AsyncMock(
                return_value={
                    "func_va": "0x101be0b0",
                    "func_rva": "0x1be0b0",
                    "func_size": "0x5a",
                    "func_sig": "55 8B EC",
                }
            )
            locate = AsyncMock(
                return_value={
                    "pointer_size": 4,
                    "sites": [
                        {
                            "ea": "0x101be0d6",
                            "mnem": "call",
                            "disasm": "call Cvar_DirectSet",
                            "insn_len": 5,
                            "patch_sig": "E8 AA BB CC DD 83 C4 08",
                            "patch_sig_disp": 0,
                        }
                    ],
                }
            )
            find_unique = AsyncMock(return_value=0x101BE0D6)

            with (
                patch.object(script, "_inspect_function_via_mcp", inspect),
                patch.object(script, "_locate_callsites", locate),
                patch.object(script, "_find_unique_bytes", find_unique),
                patch.object(script, "write_patch_yaml") as write_patch_yaml,
            ):
                result = await script.preprocess_skill(
                    session="session",
                    skill_name="find-Cvar_Set_to_Cvar_DirectSet_callsites",
                    expected_outputs=[output],
                    old_yaml_map=None,
                    new_binary_dir=binary_dir,
                    platform="windows",
                    image_base=0x10000000,
                )

        self.assertIs(result, True)
        inspect.assert_awaited_once_with(
            "session",
            0x101BE0B0,
            0x10000000,
            "Cvar_Set",
            allow_across_function_boundary=False,
        )
        locate.assert_awaited_once_with("session", 0x101BE0B0, 0x101BDB80)
        find_unique.assert_awaited_once_with("session", "E8 AA BB CC DD 83 C4 08")
        write_patch_yaml.assert_called_once_with(
            output,
            {
                "patch_name": "Cvar_Set_to_Cvar_DirectSet_callsite_0",
                "patch_va": hex(0x101BE0D6),
                "patch_rva": hex(0x1BE0D6),
                "patch_sig": "E8 AA BB CC DD 83 C4 08",
                "patch_sig_disp": 0,
            },
        )
        self.assertNotIn("patch_bytes", write_patch_yaml.call_args.args[1])

    async def test_fails_when_found_count_does_not_match_expected(self):
        script = _load_script()
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            (binary_dir / "Cvar_Set.windows.yaml").write_text(
                "func_name: Cvar_Set\nfunc_va: '0x101be0b0'\n",
                encoding="utf-8",
            )
            (binary_dir / "Cvar_DirectSet.windows.yaml").write_text(
                "func_name: Cvar_DirectSet\nfunc_va: '0x101bdb80'\n",
                encoding="utf-8",
            )
            inspect = AsyncMock(
                return_value={
                    "func_va": "0x101be0b0",
                    "func_sig": "55 8B EC",
                }
            )
            locate = AsyncMock(
                return_value={
                    "pointer_size": 4,
                    "sites": [
                        {
                            "ea": "0x101be0d6",
                            "insn_len": 5,
                            "patch_sig": "E8 AA BB CC DD",
                            "patch_sig_disp": 0,
                        },
                        {
                            "ea": "0x101be0e0",
                            "insn_len": 5,
                            "patch_sig": "E9 AA BB CC DD",
                            "patch_sig_disp": 0,
                        },
                    ],
                }
            )

            with (
                patch.object(script, "_inspect_function_via_mcp", inspect),
                patch.object(script, "_locate_callsites", locate),
                patch.object(script, "write_patch_yaml") as write_patch_yaml,
            ):
                result = await script.preprocess_skill(
                    session="session",
                    skill_name="find-Cvar_Set_to_Cvar_DirectSet_callsites",
                    expected_outputs=[binary_dir / "Cvar_Set_to_Cvar_DirectSet_callsite_0.windows.yaml"],
                    old_yaml_map=None,
                    new_binary_dir=binary_dir,
                    platform="windows",
                    image_base=0x10000000,
                )

        self.assertIs(result, False)
        write_patch_yaml.assert_not_called()


class PatchRelocationTests(unittest.IsolatedAsyncioTestCase):
    async def test_relocates_patch_signature_without_patch_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = Path(temporary) / "old.yaml"
            old_path.write_text(
                "patch_name: Cvar_Set_to_Cvar_DirectSet_callsite_0\n"
                "patch_sig: E8 AA BB CC DD 83 C4 08\n"
                "patch_sig_disp: 0\n",
                encoding="utf-8",
            )
            session = AsyncMock()
            with patch("ida_analyze_util._find_unique_bytes", AsyncMock(return_value=0x101BE0D6)):
                result = await preprocess_patch_via_mcp(
                    session,
                    Path(temporary) / "Cvar_Set_to_Cvar_DirectSet_callsite_0.windows.yaml",
                    old_path,
                    0x10000000,
                    Path(temporary),
                    "windows",
                )

        self.assertEqual(
            {
                "patch_name": "Cvar_Set_to_Cvar_DirectSet_callsite_0",
                "patch_va": hex(0x101BE0D6),
                "patch_rva": hex(0x1BE0D6),
                "patch_sig": "E8 AA BB CC DD 83 C4 08",
                "patch_sig_disp": 0,
            },
            result,
        )
        self.assertNotIn("patch_bytes", result)


if __name__ == "__main__":
    unittest.main()
