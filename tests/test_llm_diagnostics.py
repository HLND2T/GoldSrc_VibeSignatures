import contextlib
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ida_llm_decompile import LlmConfig, call_llm_decompile, request_text

VALID = "found_call:\n  - insn_va: '0x401020'\n    insn_disasm: call sub_402000\n    func_name: build_number\n"


def response(text=VALID, *, status="completed", reason=None, output=None):
    payload = {"status": status, "incomplete_details": {"reason": reason}, "output": output or []}
    return SimpleNamespace(output_text=text, model_dump=lambda **_: payload, **payload)


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
        self.assertEqual("empty_output", events[-1]["reason"])
        self.assertEqual(3, events[-1]["attempt"])

    async def test_truncated_output_is_retried_even_when_text_is_valid_yaml(self):
        for text in ("", VALID):
            with self.subTest(text=text):
                create = Mock(side_effect=[response(text, status="incomplete", reason="max_output_tokens"), response()])
                result, events = await self.run_call(
                    debug=True, client=SimpleNamespace(responses=SimpleNamespace(create=create)), max_retries=2
                )
                self.assertEqual(2, create.call_count)
                self.assertTrue(result["found_call"])
                retry = next(event for event in events if event["event"] == "retry")
                self.assertEqual("output_truncated", retry["reason"])
                failure = next(event for event in events if event["event"] == "response_extraction_failed")
                self.assertEqual("incomplete", failure["response_status"])
                self.assertEqual("max_output_tokens", failure["incomplete_reason"])
                self.assertEqual(1, sum(event["event"] == "validation" for event in events))

    async def test_correction_then_truncation_preserves_history_and_total_budget(self):
        create = Mock(
            side_effect=[
                response("not: [valid"),
                response("partial", status="incomplete", reason="max_output_tokens"),
                response(),
            ]
        )
        result, events = await self.run_call(
            debug=True, client=SimpleNamespace(responses=SimpleNamespace(create=create)), max_retries=3
        )
        self.assertTrue(result["found_call"])
        self.assertEqual(3, create.call_count)
        inputs = [call.kwargs["input"] for call in create.call_args_list]
        self.assertEqual(inputs[1], inputs[2])
        self.assertIn("complete YAML", str(inputs[2]))
        self.assertNotIn({"role": "assistant", "content": "partial"}, inputs[2])

    async def test_unknown_incomplete_status_does_not_accept_text(self):
        create = Mock(return_value=response(VALID, status="incomplete", reason="unknown"))
        result, events = await self.run_call(
            debug=True, client=SimpleNamespace(responses=SimpleNamespace(create=create))
        )
        self.assertEqual(1, create.call_count)
        self.assertFalse(any(result.values()))
        self.assertEqual("output_incomplete", events[-1]["reason"])

    async def test_empty_custom_transport_uses_output_retry_classification(self):
        transport = Mock(side_effect=["", VALID])
        result, events = await self.run_call(debug=True, call_llm_text_func=transport, max_retries=2)
        self.assertTrue(result["found_call"])
        self.assertEqual(2, transport.call_count)
        self.assertEqual("empty_output", next(event for event in events if event["event"] == "retry")["reason"])

    async def test_empty_output_can_recover_and_output_retries_are_bounded(self):
        create = Mock(side_effect=[response(" \n"), response()])
        result, _ = await self.run_call(client=SimpleNamespace(responses=SimpleNamespace(create=create)), max_retries=2)
        self.assertTrue(result["found_call"])
        self.assertEqual(2, create.call_count)
        for reply, expected in (
            (response(""), "empty_output"),
            (response(VALID, status="incomplete", reason="max_output_tokens"), "output_truncated"),
        ):
            with self.subTest(reason=expected):
                create = Mock(return_value=reply)
                result, events = await self.run_call(
                    debug=True, client=SimpleNamespace(responses=SimpleNamespace(create=create)), max_retries=3
                )
                self.assertEqual(3, create.call_count)
                self.assertFalse(any(result.values()))
                self.assertEqual(expected, events[-1]["reason"])

    async def test_refusal_and_content_filter_do_not_retry_or_accept_partial_text(self):
        replies = [
            response(VALID, status="incomplete", reason="content_filter"),
            response(VALID, output=[{"type": "message", "content": [{"type": "refusal", "refusal": "Declined"}]}]),
            response(VALID, output=[SimpleNamespace(type="message", content=[SimpleNamespace(type="refusal")])]),
        ]
        for reply in replies:
            with self.subTest(reply=reply):
                create = Mock(return_value=reply)
                result, events = await self.run_call(
                    debug=True, client=SimpleNamespace(responses=SimpleNamespace(create=create)), max_retries=3
                )
                self.assertEqual(1, create.call_count)
                self.assertFalse(any(result.values()))
                self.assertEqual("output_refused", events[-1]["reason"])

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
