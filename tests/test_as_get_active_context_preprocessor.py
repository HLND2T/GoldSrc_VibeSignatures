import importlib
import unittest
from unittest.mock import AsyncMock, patch

finder = importlib.import_module("ida_preprocessor_scripts.find-asGetActiveContext")


class AsGetActiveContextFinderTests(unittest.IsolatedAsyncioTestCase):
    async def test_platform_body_signature_routes_and_discovery_is_not_a_prior_artifact(self):
        expected = {
            "windows": "8B 48 04 85 C9 74 ?? 8B 00 8B 44 88 FC",
            "linux": "8B 50 04 85 D2 74 ?? 8B 00 8B 44 90 FC",
        }
        self.assertEqual(set(expected), set(finder.BODY_SIGNATURES))
        for platform, signature in expected.items():
            with self.subTest(platform=platform):
                self.assertEqual(signature, finder.BODY_SIGNATURES[platform])
                with patch.object(finder, "preprocess_common_skill", AsyncMock(return_value=True)) as common:
                    result = await finder.preprocess_skill(
                        object(),
                        "find-asGetActiveContext",
                        [f"asGetActiveContext.{platform}.yaml"],
                        {"asGetActiveContext": {"func_sig": "DE AD BE EF"}},
                        None,
                        platform,
                        0,
                    )
                self.assertTrue(result)
                kwargs = common.await_args.kwargs
                self.assertIsNone(kwargs["old_yaml_map"])
                self.assertEqual(["asGetActiveContext"], kwargs["func_names"])
                self.assertEqual([signature], kwargs["func_xrefs"][0]["xref_signatures"])

    async def test_body_signature_encodes_the_tail_index_statement_not_the_header(self):
        # The anchor must be the source statement `activeContexts[GetLength()-1]`:
        # it begins with the count load (`8B`, not a call/prologue) and never
        # carries whole-function header bytes.
        for signature in finder.BODY_SIGNATURES.values():
            with self.subTest(signature=signature):
                self.assertTrue(signature.startswith("8B "))
                self.assertNotIn("E8", signature.split(" ")[:1])

    async def test_failure_propagates_without_emitting(self):
        with patch.object(finder, "preprocess_common_skill", AsyncMock(return_value=False)):
            result = await finder.preprocess_skill(
                object(),
                "find-asGetActiveContext",
                ["asGetActiveContext.windows.yaml"],
                {},
                None,
                "windows",
                0,
            )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
