import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _client_body_patterns as locator


class ClientBodyPatternTests(unittest.IsolatedAsyncioTestCase):
    async def test_ambiguous_first_pattern_cannot_fall_through_to_unique_later_pattern(self):
        with (
            patch.object(locator, "_find_byte_matches", AsyncMock(side_effect=[[0x1000, 0x2000], [0x3000]])) as find,
            patch.object(locator, "_inspect_function_via_mcp", AsyncMock()) as inspect,
            patch.object(locator, "write_func_yaml") as write,
        ):
            result = await locator.preprocess_body_patterns(None, [], {"Example": ["AA", "BB"]}, 0)
        self.assertFalse(result)
        self.assertEqual(1, find.await_count)
        inspect.assert_not_awaited()
        write.assert_not_called()

    async def test_group_failure_does_not_write_earlier_valid_outputs(self):
        session = SimpleNamespace(call_tool=AsyncMock(return_value={"owner": 0x1000}))
        candidate = dict(func_name="First", func_sig="AA", func_va="0x1000", func_rva="0x1000", func_size="0x1")
        with (
            patch.object(locator, "_find_byte_matches", AsyncMock(side_effect=[[0x1000], []])),
            patch.object(locator, "parse_mcp_result", side_effect=lambda value: value),
            patch.object(locator, "_inspect_function_via_mcp", AsyncMock(return_value=candidate)),
            patch.object(locator, "_output_for_symbol", return_value="First.yaml"),
            patch.object(locator, "write_func_yaml") as write,
        ):
            result = await locator.preprocess_body_patterns(session, [], {"First": ["AA"], "Second": ["BB"]}, 0)
        self.assertFalse(result)
        write.assert_not_called()

    async def test_cross_boundary_output_requires_a_successful_second_inspection(self):
        session = SimpleNamespace(call_tool=AsyncMock(return_value={"owner": 0x1000}))
        candidate = dict(func_name="Example", func_sig="AA BB", func_va="0x1000", func_rva="0x1000", func_size="0x1")
        with (
            patch.object(locator, "_find_byte_matches", AsyncMock(return_value=[0x1000])),
            patch.object(locator, "parse_mcp_result", side_effect=lambda value: value),
            patch.object(locator, "_inspect_function_via_mcp", AsyncMock(side_effect=[None, candidate])) as inspect,
            patch.object(locator, "_output_for_symbol", return_value="Example.yaml"),
            patch.object(locator, "write_func_yaml") as write,
        ):
            result = await locator.preprocess_body_patterns(session, [], {"Example": ["AA"]}, 0)
        self.assertTrue(result)
        self.assertEqual(2, inspect.await_count)
        inspect.assert_awaited_with(session, 0x1000, 0, "Example", allow_across_function_boundary=True)
        write.assert_called_once_with("Example.yaml", {**candidate, "func_sig_allow_across_function_boundary": True})
