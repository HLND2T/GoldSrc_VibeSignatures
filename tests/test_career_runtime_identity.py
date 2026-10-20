import unittest

from ida_preprocessor_scripts._career_runtime_identity import common_pointer_chain, pointer_chain


class PointerPathTests(unittest.TestCase):
    def test_distinct_layouts_are_decoded(self):
        for root, active, directory in ((0x1000, 12, 24), (0x2000, 20, 36)):
            value = ("load", ("load", ("load", ("const", root), 0), active), directory)
            self.assertEqual((root, [active, directory]), common_pointer_chain([value, value], 3))

    def test_ambiguous_incomplete_or_unaligned_paths_refuse(self):
        good = ("load", ("const", 0x1000), 0)
        for values in ([], [good, ("load", ("const", 0x2000), 0)]):
            with self.assertRaises(ValueError):
                common_pointer_chain(values, 1)
        for value in (None, ("const", 0x1000), ("load", ("arg", 0), 0), ("load", ("const", 0x1000), 1)):
            with self.assertRaises(ValueError):
                pointer_chain(value, 1)
