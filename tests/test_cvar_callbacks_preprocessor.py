import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "ida_preprocessor_scripts" / "find-cvar_callbacks.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("find_cvar_callbacks_under_test", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CvarCallbacksPreprocessorTests(unittest.IsolatedAsyncioTestCase):
    def test_locator_snippet_compiles_after_address_substitution(self):
        script = _load_script()
        code = script.LOCATE_PY.replace("CVAR_SET_EA_PLACEHOLDER", "0x101be0b0").replace(
            "CVAR_DIRECTSET_EA_PLACEHOLDER", "0x101bdb80"
        )

        compile(code, str(SCRIPT_PATH), "exec")

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
                skill_name="find-cvar_callbacks",
                expected_outputs=[binary_dir / "cvar_callbacks.windows.yaml"],
                old_yaml_map=None,
                new_binary_dir=binary_dir,
                platform="windows",
                image_base=0x10000000,
            )

        self.assertIs(result, False)

    async def test_passes_verified_artifact_addresses_to_locator(self):
        script = _load_script()
        with tempfile.TemporaryDirectory() as temporary:
            binary_dir = Path(temporary)
            output = binary_dir / "cvar_callbacks.windows.yaml"
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
                    "gv_ea": "0x104b74c8",
                    "insn_ea": "0x101be0e1",
                    "insn_len": 5,
                    "insn_disp": 1,
                }
            )

            with (
                patch.object(script, "_inspect_function_via_mcp", inspect),
                patch.object(script, "_locate_cvar_callbacks", locate),
                patch.object(script, "write_gv_yaml") as write_gv_yaml,
            ):
                result = await script.preprocess_skill(
                    session="session",
                    skill_name="find-cvar_callbacks",
                    expected_outputs=[output],
                    old_yaml_map=None,
                    new_binary_dir=binary_dir,
                    platform="windows",
                    image_base=0x10000000,
                )

        self.assertIs(result, True)
        inspect.assert_awaited_once_with("session", 0x101BE0B0, 0x10000000, "Cvar_Set")
        locate.assert_awaited_once_with("session", 0x101BE0B0, 0x101BDB80)
        write_gv_yaml.assert_called_once_with(
            output,
            {
                "gv_name": "cvar_callbacks",
                "gv_va": "0x104b74c8",
                "gv_rva": "0x4b74c8",
                "gv_sig": "55 8B EC",
                "gv_sig_va": "0x101be0b0",
                "gv_inst_offset": "0x31",
                "gv_inst_length": "0x5",
                "gv_inst_disp": "0x1",
            },
        )


if __name__ == "__main__":
    unittest.main()
