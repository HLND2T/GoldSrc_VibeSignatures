import contextlib
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ida_llm_decompile import LlmConfig, call_llm_decompile, request_text

VALID = "found_call:\n  - insn_va: '0x401020'\n    insn_disasm: call sub_402000\n    func_name: build_number\n"


class LlmDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def run_call(self, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = await call_llm_decompile(
                model="test-model",
                symbol_name_list=["build_number"],
                expected_result_sections={"build_number": ["found_call"]},
                target_disasm_codes=["0x401020: call sub_402000"],
                prompt_template=kwargs.pop("prompt_template", "Find {symbol_name_list}."),
                retry_initial_delay=0,
                **kwargs,
            )
        events = [json.loads(line.removeprefix("LLM diagnostic: ")) for line in output.getvalue().splitlines()]
        return result, events

    async def test_full_response_and_request_are_redacted_and_correlated(self):
        secret = 'test-key-"\\secret'
        long_text = "x" * 20000
        payload = {
            "output": [{"text": VALID}],
            "metadata": long_text + secret,
            "headers": {"Authorization": "Bearer private"},
        }
        response = SimpleNamespace(output_text=VALID, model_dump=lambda **_: payload)
        client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_: response))
        result, events = await self.run_call(
            debug=True, client=client, api_key=secret, prompt_template=secret + " {symbol_name_list}"
        )
        self.assertEqual("build_number", result["found_call"][0]["func_name"])
        self.assertEqual(1, len({event["call_id"] for event in events}))
        self.assertEqual({1}, {event["attempt"] for event in events})
        raw = next(event["response"] for event in events if event["event"] == "api_response")
        self.assertEqual(long_text + "[REDACTED]", raw["metadata"])
        self.assertEqual("[REDACTED]", raw["headers"])
        self.assertNotIn(secret, json.dumps(events))
        request = next(event for event in events if event["event"] == "request")
        self.assertIn("[REDACTED]", request["messages"][1]["content"])

    async def test_invalid_schema_and_semantics_keep_correction_history(self):
        replies = iter(["not: [valid", VALID.replace("0x401020", "0x999999"), VALID])
        _, events = await self.run_call(debug=True, max_retries=3, call_llm_text_func=lambda **_: next(replies))
        validation = [event for event in events if event["event"] == "validation"]
        self.assertTrue(validation[0]["schema_issues"])
        self.assertTrue(validation[1]["semantic_issues"])
        self.assertEqual("succeeded", events[-1]["status"])
        self.assertEqual(3, events[-1]["attempt"])
        requests = [event for event in events if event["event"] == "request"]
        self.assertEqual([2, 4, 6], [len(event["messages"]) for event in requests])

    async def test_missing_output_keeps_raw_response(self):
        response = SimpleNamespace(output_text="", model_dump=lambda **_: {"status": "incomplete"})
        client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_: response))
        _, events = await self.run_call(debug=True, client=client)
        self.assertIn("api_response", [event["event"] for event in events])
        self.assertIn("response_extraction_failed", [event["event"] for event in events])
        self.assertEqual("transport_failed", events[-1]["reason"])

    async def test_transport_exception_and_template_failure(self):
        def fail(**_):
            raise RuntimeError("bad credential secret-value")

        _, events = await self.run_call(debug=True, api_key="secret-value", call_llm_text_func=fail)
        error = next(event for event in events if event["event"] == "request_failed")
        self.assertEqual("bad credential [REDACTED]", error["error"])
        _, events = await self.run_call(debug=True, prompt_template="{unknown_placeholder}")
        self.assertEqual("template_failed", events[-1]["reason"])

    async def test_exhausted_validation_and_transient_retry(self):
        _, events = await self.run_call(debug=True, max_retries=1, call_llm_text_func=lambda **_: "not: [valid")
        self.assertEqual("validation_retries_exhausted", events[-1]["reason"])
        replies = iter([TimeoutError("timed out"), VALID])

        def transport(**_):
            value = next(replies)
            if isinstance(value, Exception):
                raise value
            return value

        _, events = await self.run_call(debug=True, max_retries=2, call_llm_text_func=transport)
        self.assertIn("retry", [event["event"] for event in events])
        self.assertEqual("succeeded", events[-1]["status"])

    async def test_debug_disabled_and_broken_logging_preserve_results(self):
        expected, events = await self.run_call(debug=False, call_llm_text_func=lambda **_: VALID)
        self.assertEqual([], events)
        with patch("builtins.print", side_effect=OSError("closed output")):
            actual, events = await self.run_call(debug=True, call_llm_text_func=lambda **_: VALID)
        self.assertEqual(expected, actual)
        self.assertEqual([], events)

    def test_callback_and_serialization_failures_do_not_change_transport(self):
        def fail(*_, **__):
            raise RuntimeError("broken diagnostic")

        response = SimpleNamespace(output_text=VALID, model_dump=fail)
        client = SimpleNamespace(responses=SimpleNamespace(create=lambda **_: response))
        self.assertEqual(
            VALID,
            request_text(
                [{"role": "user", "content": "Find target"}],
                config=LlmConfig(),
                client=client,
                diagnostic_callback=fail,
            ),
        )
