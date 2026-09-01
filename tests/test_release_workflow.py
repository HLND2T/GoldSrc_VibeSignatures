from __future__ import annotations

import unittest

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.manifests import require_gamever, require_sha, require_sha256, require_version


class ReleaseIdentifierTests(unittest.TestCase):
    def test_version_gamever_and_digest_validators(self):
        self.assertEqual("v20260825a", require_version("v20260825a"))
        self.assertEqual("hl-10210", require_gamever("hl-10210"))
        self.assertEqual("a" * 40, require_sha("A" * 40))
        self.assertEqual("b" * 64, require_sha256("b" * 64, "digest"))
        for bad in ("20260825a", "v2026082", "v20260825ab"):
            with self.subTest(bad=bad), self.assertRaises(ReleaseWorkflowError):
                require_version(bad)
        for bad in ("10210", "HL-10210", "hl-", "hl-10210-extra"):
            with self.subTest(bad=bad), self.assertRaises(ReleaseWorkflowError):
                require_gamever(bad)
        with self.assertRaises(ReleaseWorkflowError):
            require_sha("a" * 39)
        with self.assertRaises(ReleaseWorkflowError):
            require_sha256("B" * 64, "digest")


if __name__ == "__main__":
    unittest.main()
