from __future__ import annotations

import unittest
from pathlib import Path

from analysis_config import iter_analysis_config_tags
from generated_output_contract import GeneratedOutputContractError, validate_generated_output_contract

ROOT = Path(__file__).parents[1]


class GeneratedOutputContractTests(unittest.TestCase):
    def test_published_outputs_match_the_current_source_contract(self):
        try:
            gamevers = validate_generated_output_contract(ROOT)
        except GeneratedOutputContractError as exc:
            self.fail(str(exc))
        self.assertEqual(
            tuple(iter_analysis_config_tags(ROOT)),
            tuple(gamevers),
        )


if __name__ == "__main__":
    unittest.main()
