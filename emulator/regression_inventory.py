"""Strict structural check for two Brico68k regression JSON recordings.

Run: python emulator/regression_inventory.py OLD.json NEW.json
Self-test: python emulator/regression_inventory.py --self-test
This complements regress_rom.py; it does not interpret diagnostic outputs.
"""
import json
import sys
import unittest
from pathlib import Path


def inventory_differences(old, new):
    """Return human-readable structural changes without masking chaotic outputs."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        raise ValueError('regression recordings must be JSON objects')
    # Validate *all* scenarios before comparing inventories, including scenarios
    # that exist on only one side. Otherwise malformed new/removed scenarios pass.
    for side, recording in (('old', old), ('new', new)):
        for scenario, records in recording.items():
            if not isinstance(records, list):
                raise ValueError(f'{scenario}: {side} commands must be arrays')
            for index, rec in enumerate(records):
                if not isinstance(rec, dict) or not isinstance(rec.get('cmd'), str):
                    raise ValueError(f'{scenario}: {side} record {index} lacks string cmd')
                if not rec['cmd'].strip():
                    raise ValueError(f'{scenario}: {side} record {index} has empty cmd')
    differences = []
    for scenario in sorted(old.keys() - new.keys()):
        differences.append(f'MISSING scenario: {scenario}')
    for scenario in sorted(new.keys() - old.keys()):
        differences.append(f'ADDED scenario: {scenario}')
    for scenario in sorted(old.keys() & new.keys()):
        a = [r['cmd'] for r in old[scenario]]
        b = [r['cmd'] for r in new[scenario]]
        if a != b:
            differences.append(f'COMMANDS changed: {scenario}: {a!r} -> {b!r}')
    return differences


class InventoryTests(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(inventory_differences({'s': [{'cmd': 'A'}]}, {'s': [{'cmd': 'A'}]}), [])

    def test_added_scenario(self):
        self.assertEqual(len(inventory_differences({}, {'new': []})), 1)

    def test_removed_scenario(self):
        self.assertEqual(len(inventory_differences({'old': []}, {})), 1)

    def test_added_command(self):
        self.assertEqual(len(inventory_differences({'s': []}, {'s': [{'cmd': 'A'}]})), 1)

    def test_removed_command(self):
        self.assertEqual(len(inventory_differences({'s': [{'cmd': 'A'}]}, {'s': []})), 1)

    def test_reordered_commands(self):
        self.assertEqual(len(inventory_differences({'s': [{'cmd': 'A'}, {'cmd': 'B'}]},
                                                   {'s': [{'cmd': 'B'}, {'cmd': 'A'}]})), 1)

    def test_ignores_output_and_timing(self):
        self.assertEqual(inventory_differences({'s': [{'cmd': 'A', 'secs': 1, 'gfx': 1}]},
                                               {'s': [{'cmd': 'A', 'secs': 2, 'gfx': 2}]}), [])

    def test_malformed_record_rejected(self):
        with self.assertRaises(ValueError):
            inventory_differences({'s': [{'cmd': 'A'}]}, {'s': [{}]})

    def test_malformed_added_scenario_rejected(self):
        with self.assertRaises(ValueError):
            inventory_differences({}, {'added': [{}]})

    def test_malformed_removed_scenario_rejected(self):
        with self.assertRaises(ValueError):
            inventory_differences({'removed': 42}, {})

    def test_malformed_root_rejected(self):
        with self.assertRaises(ValueError):
            inventory_differences([], {})


    def test_empty_command_rejected_old(self):
        with self.assertRaisesRegex(ValueError, 'empty cmd'):
            inventory_differences({'s': [{'cmd': ''}]}, {'s': [{'cmd': 'Echo 1'}]})

    def test_whitespace_command_rejected_new(self):
        with self.assertRaisesRegex(ValueError, 'empty cmd'):
            inventory_differences({'s': [{'cmd': 'Echo 1'}]}, {'s': [{'cmd': ' \\t '}]})

    def test_empty_command_rejected_in_added_scenario(self):
        with self.assertRaisesRegex(ValueError, 'empty cmd'):
            inventory_differences({}, {'added': [{'cmd': ''}]})

    def test_empty_command_rejected_in_removed_scenario(self):
        with self.assertRaisesRegex(ValueError, 'empty cmd'):
            inventory_differences({'removed': [{'cmd': ' \\n'}]}, {})

def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args == ['--self-test']:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(InventoryTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        before = json.loads(Path(args[0]).read_text(encoding='utf-8'))
        after = json.loads(Path(args[1]).read_text(encoding='utf-8'))
        changes = inventory_differences(before, after)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'Invalid regression input: {exc}', file=sys.stderr)
        return 2
    for change in changes:
        print(change)
    print(f'{len(changes)} structural difference(s)')
    return 1 if changes else 0


if __name__ == '__main__':
    sys.exit(main())
