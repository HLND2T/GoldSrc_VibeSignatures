from __future__ import annotations

import importlib.util
import os
import unittest


class IdaIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("RUN_IDA_INTEGRATION") == "1", "real IDA integration is opt-in")
    def test_idalib_environment_is_activated(self):
        self.assertIsNotNone(importlib.util.find_spec("idaapi"), "idaapi is unavailable in the active interpreter")
        self.assertIsNotNone(importlib.util.find_spec("idalib"), "idalib is unavailable in the active interpreter")


if __name__ == "__main__":
    unittest.main()
