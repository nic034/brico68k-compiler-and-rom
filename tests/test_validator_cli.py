"""CLI tests for the regression JSON validator (no emulator required)."""
import contextlib
import io
import json
import tempfile
import unittest
import importlib.util
from pathlib import Path

VALIDATOR = Path(__file__).resolve().parents[1] / "emulator" / "validate_regression_records.py"
spec = importlib.util.spec_from_file_location("brico_validator_cli", VALIDATOR)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
main = module.main


class ValidatorCliTests(unittest.TestCase):
    def test_valid(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ok.json"
            p.write_text(json.dumps({"healthy/none": [{"cmd": "Echo 1", "status": "eot"}]}))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(p)]), 0)
            self.assertIn("OK ", out.getvalue())

    def test_invalid_record(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text(json.dumps({"healthy/none": [{"cmd": "", "status": "eot"}]}))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(p)]), 1)
            self.assertIn("empty cmd", out.getvalue())

    def test_bad_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.json"
            p.write_text("{")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(p)]), 1)
            self.assertIn("INVALID ", out.getvalue())

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(Path(d) / "missing.json")]), 1)
            self.assertIn("INVALID ", out.getvalue())

    def test_multiple_files_continue_after_failure(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a.json", Path(d) / "b.json"
            a.write_text("bad")
            b.write_text("{}")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main([str(a), str(b)]), 1)
            self.assertIn("OK ", out.getvalue())


if __name__ == "__main__":
    unittest.main()
