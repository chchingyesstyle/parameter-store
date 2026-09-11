import tempfile
import unittest
from pathlib import Path

from app import ParameterError, ParameterStore


class ParameterStoreTests(unittest.TestCase):
    def test_put_and_get_parameter(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ParameterStore(Path(tmp) / "parameters.db")

            store.put("region", "eu-west-2")

            self.assertEqual(store.get("region"), "eu-west-2")

    def test_put_overwrites_and_list_returns_sorted_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ParameterStore(Path(tmp) / "parameters.db")

            store.put("zone", "b")
            store.put("account", "a")
            store.put("zone", "updated")

            items = store.list()

            self.assertEqual([item["parameter"] for item in items], ["account", "zone"])
            self.assertEqual([item["value"] for item in items], ["a", "updated"])

    def test_list_treats_wildcards_as_literal_query_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ParameterStore(Path(tmp) / "parameters.db")
            store.put("plain", "one")
            store.put("other", "two")

            items = store.list("%")

            self.assertEqual(items, [])

    def test_delete_removes_parameter_and_reports_whether_it_existed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ParameterStore(Path(tmp) / "parameters.db")
            store.put("temporary", "value")

            self.assertTrue(store.delete("temporary"))
            self.assertIsNone(store.get("temporary"))
            self.assertFalse(store.delete("temporary"))

    def test_rejects_invalid_parameter_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ParameterStore(Path(tmp) / "parameters.db")

            with self.assertRaises(ParameterError):
                store.put("../unsafe", "value")

    def test_rejects_non_string_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ParameterStore(Path(tmp) / "parameters.db")

            with self.assertRaises(ParameterError):
                store.put("region", 2)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
