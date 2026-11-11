"""Inventory-only checks for emulator/regress_rom.py compare().

Run: python -m unittest discover -s emulator -p 'test_regress_inventory.py'
The ROM and its sources are not written by this test.
"""
import contextlib
import io
import unittest

import regress_rom


def record(cmd, status="eot"):
    return {"cmd": cmd, "status": status, "words": [], "text": "", "secs": 0.0}


class RegressionInventoryTests(unittest.TestCase):
    def check(self, old, new):
        with contextlib.redirect_stdout(io.StringIO()):
            return regress_rom.compare(old, new)

    def test_identical_inventory(self):
        self.assertEqual(self.check({"healthy/none": [record("Echo 1")]},
                                    {"healthy/none": [record("Echo 1")]}), 0)

    def test_added_scenario(self):
        self.assertGreater(self.check({}, {"healthy/none": [record("Echo 1")]}), 0)

    def test_removed_scenario(self):
        self.assertGreater(self.check({"healthy/none": [record("Echo 1")]}, {}), 0)

    def test_added_command(self):
        self.assertGreater(self.check({"healthy/none": [record("Echo 1")]},
                                      {"healthy/none": [record("Echo 1"), record("Echo 2")]}), 0)

    def test_removed_command(self):
        self.assertGreater(self.check({"healthy/none": [record("Echo 1"), record("Echo 2")]},
                                      {"healthy/none": [record("Echo 1")]}), 0)

    def test_reordered_commands(self):
        self.assertGreater(self.check({"healthy/none": [record("Echo 1"), record("Echo 2")]},
                                      {"healthy/none": [record("Echo 2"), record("Echo 1")]}), 0)

    def test_unstable_cart_command_inventory(self):
        scenario = "fault/test/cart:float:3"
        self.assertGreater(self.check({scenario: [record("CartTest")]},
                                      {scenario: [record("CartTest"), record("CartTest 1")]}), 0)


if __name__ == "__main__":
    unittest.main()
