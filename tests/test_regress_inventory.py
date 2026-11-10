"""Focused regression tests for the ROM result inventory comparator.

Run from repository root:
    python -m unittest discover -s tests -p 'test_regress_inventory.py' -v

The comparator is loaded from its AST so tests need no emulator shared library.
"""
import ast
import contextlib
import difflib
import io
from collections import defaultdict
from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "emulator" / "regress_rom.py"
tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
compare_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "compare")
module = ast.fix_missing_locations(ast.Module(body=[compare_node], type_ignores=[]))
namespace = {"re": re, "defaultdict": defaultdict, "difflib": difflib}
exec(compile(module, str(SOURCE), "exec"), namespace)
compare = namespace["compare"]


def record(cmd="Echo 1", status="eot"):
    return {"cmd": cmd, "status": status, "words": [1], "text": "ok",
            "secs": 0.1, "z80": 0, "cartw": 0, "latchw": 0, "overflow": 0}


def check(old, new):
    with contextlib.redirect_stdout(io.StringIO()) as output:
        differences = compare(old, new)
    return differences, output.getvalue()


class InventoryRegressionTests(unittest.TestCase):
    def test_identical(self):
        differences, _ = check({"healthy/none": [record()]}, {"healthy/none": [record()]})
        self.assertEqual(differences, 0)

    def test_missing_scenario(self):
        differences, output = check({"healthy/none": [record()]}, {})
        self.assertGreater(differences, 0)
        self.assertIn("MISSING scenario", output)

    def test_extra_scenario(self):
        differences, output = check({}, {"healthy/none": [record()]})
        self.assertGreater(differences, 0)
        self.assertIn("EXTRA scenario", output)

    def test_missing_command(self):
        differences, output = check({"healthy/none": [record(), record("Echo 2")]},
                                    {"healthy/none": [record()]})
        self.assertGreater(differences, 0)
        self.assertIn("command count", output)

    def test_reordered_command(self):
        old = [record("Echo 1"), record("Echo 2")]
        new = list(reversed(old))
        differences, output = check({"healthy/none": old}, {"healthy/none": new})
        self.assertGreater(differences, 0)
        self.assertIn("DIFF command", output)

    def test_chaotic_scenario_still_checks_inventory(self):
        scenario = "fault/bios:float:1"
        differences, _ = check({scenario: [record()]}, {scenario: []})
        self.assertGreater(differences, 0)

    def test_random_cart_scenario_still_checks_inventory(self):
        scenario = "fault/test/cart:float:0"
        differences, _ = check({scenario: [record()]}, {scenario: []})
        self.assertGreater(differences, 0)


if __name__ == "__main__":
    unittest.main()
