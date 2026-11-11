"""Isolated tests for the real regress_rom.compare function, without loading a ROM.

The function is extracted from its source AST so importing regress_rom does not
initialize the native emulator. Run: python3 -m unittest emulator.test_regress_inventory
"""
import ast
import contextlib
import difflib
import io
import re
import unittest
from collections import defaultdict
from pathlib import Path


def load_compare():
    path = Path(__file__).with_name("regress_rom.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    fn = next(node for node in tree.body
              if isinstance(node, ast.FunctionDef) and node.name == "compare")
    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))
    namespace = {"re": re, "defaultdict": defaultdict, "difflib": difflib}
    exec(compile(module, str(path), "exec"), namespace)
    return namespace["compare"]


def record(command):
    return {"cmd": command, "status": "timeout", "words": []}


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compare = staticmethod(load_compare())

    def check(self, old, new, expected):
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.compare(old, new)
        self.assertEqual(result, expected)

    def test_unchanged(self):
        self.check({"healthy": [record("A")]},
                   {"healthy": [record("A")]}, 0)

    def test_added_scenario(self):
        self.check({}, {"added": []}, 1)

    def test_removed_scenario(self):
        self.check({"removed": []}, {}, 1)

    def test_trailing_command_added(self):
        self.check({"healthy": [record("A")]},
                   {"healthy": [record("A"), record("B")]}, 1)

    def test_trailing_command_removed(self):
        self.check({"healthy": [record("A"), record("B")]},
                   {"healthy": [record("A")]}, 1)

    def test_command_reordered(self):
        self.check({"healthy": [record("A"), record("B")]},
                   {"healthy": [record("B"), record("A")]}, 2)

    def test_command_changed_in_random_fault(self):
        # The cart:float special case must still enforce command inventory.
        self.check({"fault/test/cart:float:1": [record("A")]},
                   {"fault/test/cart:float:1": [record("B")]}, 1)


if __name__ == "__main__":
    unittest.main()
