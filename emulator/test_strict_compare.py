"""Unit tests for the combined regression comparison runner."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strict_compare import main


class StrictCompareTests(unittest.TestCase):
    def run_case(self, old, new, comparator=0):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [Path(tmp) / f'{i}.json' for i in range(2)]
            for path, value in zip(paths, (old, new)):
                path.write_text(json.dumps(value), encoding='utf-8')
            calls = []

            def runner(argv, check):
                calls.append((argv, check))
                return SimpleNamespace(returncode=comparator)

            rc = main([str(p) for p in paths], runner=runner)
            return rc, calls

    def test_equal(self):
        rc, calls = self.run_case({'s': [{'cmd': 'A'}]}, {'s': [{'cmd': 'A'}]})
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][2], 'compare')

    def test_added_scenario_detected(self):
        rc, calls = self.run_case({}, {'new': []})
        self.assertEqual(rc, 1)
        self.assertEqual(len(calls), 1)

    def test_command_reorder_detected(self):
        rc, _ = self.run_case({'s': [{'cmd': 'A'}, {'cmd': 'B'}]},
                              {'s': [{'cmd': 'B'}, {'cmd': 'A'}]})
        self.assertEqual(rc, 1)

    def test_gfx_difference_preserved_by_comparator(self):
        rc, calls = self.run_case({'s': [{'cmd': 'TestGfx', 'gfx': 1}]},
                                  {'s': [{'cmd': 'TestGfx', 'gfx': 2}]}, 1)
        self.assertEqual(rc, 1)
        self.assertEqual(len(calls), 1)

    def test_invalid_record_fails_closed(self):
        rc, calls = self.run_case({'s': [{'cmd': 'A'}]}, {'s': [{}]})
        self.assertEqual(rc, 2)
        self.assertFalse(calls)

    def test_comparator_error_fails_closed(self):
        rc, _ = self.run_case({}, {}, 3)
        self.assertEqual(rc, 2)

    def test_usage(self):
        self.assertEqual(main([], runner=lambda *_: None), 2)


    def test_empty_command_fails_before_launching_comparator(self):
        rc, calls = self.run_case({'s': [{'cmd': 'Echo 1'}]}, {'s': [{'cmd': '\t  '}]})
        self.assertEqual(rc, 2)
        self.assertFalse(calls)


if __name__ == '__main__':
    unittest.main()
