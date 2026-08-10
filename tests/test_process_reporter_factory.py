import unittest
from types import SimpleNamespace
from unittest.mock import patch

from process_reporter import ConsoleProcessReporter, NullProcessReporter, ProcessReporterConfigurationError
from process_reporter_factory import create_process_reporter


class TestProcessReporterFactory(unittest.TestCase):
    def test_defaults_to_null_reporter(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            reporter = create_process_reporter(SimpleNamespace())

        self.assertIsInstance(reporter, NullProcessReporter)

    def test_rejects_unknown_backend(self) -> None:
        with self.assertRaisesRegex(ProcessReporterConfigurationError, "Unsupported"):
            create_process_reporter(SimpleNamespace(process_reporter="unknown"))

    def test_constructs_console_backend(self) -> None:
        self.assertIsInstance(
            create_process_reporter(SimpleNamespace(process_reporter="console")), ConsoleProcessReporter
        )

    @patch("process_reporter_redis.RedisProcessReporter")
    def test_redis_backend_receives_connection_settings_and_safe_metadata(self, reporter_type) -> None:
        reporter_type.return_value = object()
        args = SimpleNamespace(
            process_reporter="redis",
            redis_url="redis://example:6379/2",
            redis_prefix="test:prefix",
            gamever="svencoop-10257",
            agent="codex",
            configyaml="custom.yaml",
            llm_apikey="secret",
        )

        reporter = create_process_reporter(args)

        self.assertIs(reporter_type.return_value, reporter)
        reporter_type.assert_called_once_with(
            redis_url="redis://example:6379/2",
            prefix="test:prefix",
            run_metadata={"gamever": "svencoop-10257", "agent": "codex", "config_path": "custom.yaml"},
        )


if __name__ == "__main__":
    unittest.main()
