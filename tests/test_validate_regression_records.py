import unittest
from emulator.validate_regression_records import validate_records


class ValidateRecordsTests(unittest.TestCase):
    def test_valid(self):
        validate_records({"healthy/none": [{"cmd": "Echo 1", "status": "eot"}]}, "old")

    def test_empty_inventory(self):
        validate_records({}, "new")

    def test_empty_command(self):
        with self.assertRaisesRegex(ValueError, "empty cmd"):
            validate_records({"healthy/none": [{"cmd": "   ", "status": "eot"}]}, "old")

    def test_missing_command(self):
        with self.assertRaisesRegex(ValueError, "empty cmd"):
            validate_records({"healthy/none": [{"status": "eot"}]}, "old")

    def test_wrong_record(self):
        with self.assertRaisesRegex(ValueError, "record object"):
            validate_records({"healthy/none": [None]}, "new")

    def test_wrong_scenario(self):
        with self.assertRaisesRegex(ValueError, "scenario entry"):
            validate_records({"healthy/none": {}}, "new")

    def test_missing_status(self):
        with self.assertRaisesRegex(ValueError, "status"):
            validate_records({"healthy/none": [{"cmd": "Echo 1"}]}, "old")

    def test_wrong_root(self):
        with self.assertRaisesRegex(ValueError, "scenario dictionary"):
            validate_records([], "old")


    def test_blank_scenario(self):
        with self.assertRaisesRegex(ValueError, "scenario entry"):
            validate_records({"  ": []}, "old")

    def test_blank_status(self):
        with self.assertRaisesRegex(ValueError, "status"):
            validate_records({"healthy/none": [{"cmd": "Echo 1", "status": "  "}]}, "new")


if __name__ == "__main__":
    unittest.main()
