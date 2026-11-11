"""Run Brico68k structural and diagnostic regression checks together.

Usage: python emulator/strict_compare.py OLD.json NEW.json
Exit codes: 0 equal, 1 differences, 2 invalid input or execution failure.
"""
import json
import subprocess
import sys
from pathlib import Path

from regression_inventory import inventory_differences


def main(argv=None, runner=subprocess.run):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        old, new = [json.loads(Path(p).read_text(encoding='utf-8')) for p in args]
        changes = inventory_differences(old, new)
    except (OSError, ValueError, TypeError) as exc:
        print(f'Invalid regression input: {exc}', file=sys.stderr)
        return 2
    for change in changes:
        print(change)
    print(f'{len(changes)} structural difference(s)')
    # The original comparator still checks gfx, status, words, timing exceptions,
    # chaotic faults and hardware side effects. Do not replace it with the guard.
    try:
        result = runner([sys.executable, str(Path(__file__).with_name('regress_rom.py')),
                         'compare', *args], check=False)
    except OSError as exc:
        print(f'Comparator execution failed: {exc}', file=sys.stderr)
        return 2
    if result.returncode not in (0, 1):
        print(f'Comparator failed with exit code {result.returncode}', file=sys.stderr)
        return 2
    return 1 if changes or result.returncode else 0


if __name__ == '__main__':
    sys.exit(main())
