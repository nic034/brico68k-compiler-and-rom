"""Validate the shape of Brico68k regression JSON before comparing results."""


def validate_records(results, label):
    if not isinstance(results, dict):
        raise ValueError(f"{label}: expected a scenario dictionary")
    for scenario, records in results.items():
        if not isinstance(scenario, str) or not scenario.strip() or not isinstance(records, list):
            raise ValueError(f"{label}: invalid scenario entry {scenario!r}")
        # compare() parses this field as an integer for BIOS address-line faults.
        if scenario.startswith("fault/bios:addr:"):
            parts = scenario.split(":")
            if len(parts) != 3 or not parts[2].isdecimal():
                raise ValueError(f"{label}: invalid BIOS address-line scenario {scenario!r}")
        for index, record in enumerate(records):
            where = f"{label}/{scenario}[{index}]"
            if not isinstance(record, dict):
                raise ValueError(f"{where}: expected a record object")
            command = record.get("cmd")
            if not isinstance(command, str) or not command.strip():
                raise ValueError(f"{where}: missing or empty cmd")
            if not isinstance(record.get("status"), str) or not record["status"].strip():
                raise ValueError(f"{where}: missing or invalid status")


def main(argv=None):
    """Check one or more saved regression inventories without loading the emulator."""
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path, help="regression JSON files")
    args = parser.parse_args(argv)
    failed = False
    for path in args.files:
        try:
            with path.open(encoding="utf-8") as stream:
                records = json.load(stream)
            validate_records(records, str(path))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            print(f"INVALID {path}: {exc}")
            failed = True
        else:
            print(f"OK {path}: {len(records)} scenarios")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
