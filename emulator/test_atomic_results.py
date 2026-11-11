"""Run with: python -m unittest discover -s emulator -p test_atomic_results.py"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atomic_results import write_results


class AtomicResultsTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'results.json'

    def assert_no_temps(self):
        self.assertEqual(list(self.path.parent.glob('.results.json.*.tmp')), [])

    def test_creates_complete_json(self):
        write_results(self.path, {'scenario': [{'cmd': 'Echo 1', 'status': 'eot'}]})
        self.assertEqual(json.loads(self.path.read_text()), {'scenario': [{'cmd': 'Echo 1', 'status': 'eot'}]})
        self.assert_no_temps()

    def test_replaces_existing_json(self):
        self.path.write_text('OLD')
        write_results(self.path, {'new': []})
        self.assertEqual(json.loads(self.path.read_text()), {'new': []})
        self.assert_no_temps()

    def test_serialization_failure_preserves_previous_file(self):
        self.path.write_text('ORIGINAL')
        with self.assertRaises(TypeError):
            write_results(self.path, {'invalid': object()})
        self.assertEqual(self.path.read_text(), 'ORIGINAL')
        self.assert_no_temps()

    def test_replace_failure_preserves_previous_file(self):
        self.path.write_text('ORIGINAL')
        with patch('atomic_results.os.replace', side_effect=OSError('simulated failure')):
            with self.assertRaises(OSError):
                write_results(self.path, {'valid': 1})
        self.assertEqual(self.path.read_text(), 'ORIGINAL')
        self.assert_no_temps()

    def test_missing_directory_does_not_create_result(self):
        missing = self.path.parent / 'missing' / 'results.json'
        with self.assertRaises(FileNotFoundError):
            write_results(missing, {'valid': 1})
        self.assertFalse(missing.exists())
