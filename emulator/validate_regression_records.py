"""Validate the shape of Brico68k regression JSON before comparing results."""


def validate_records(results, label):
    if not isinstance(results, dict):
        raise ValueError(f"{label}: expected a scenario dictionary")
    for scenario, records in results.items():
        if not isinstance(scenario, str) or not scenario.strip() or not isinstance(records, list):
            raise ValueError(f"{label}: invalid scenario entry {scenario!r}")
        for index, record in enumerate(records):
            where = f"{label}/{scenario}[{index}]"
            if not isinstance(record, dict):
                raise ValueError(f"{where}: expected a record object")
            command = record.get("cmd")
            if not isinstance(command, str) or not command.strip():
                raise ValueError(f"{where}: missing or empty cmd")
            if not isinstance(record.get("status"), str) or not record["status"].strip():
                raise ValueError(f"{where}: missing or invalid status")
