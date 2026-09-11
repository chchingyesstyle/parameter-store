import base64
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from app import (
    EncryptionKeyError,
    ParameterError,
    ParameterStore,
    StorageIntegrityError,
    ValueCipher,
    load_encryption_key,
)


TEST_KEY = b"k" * 32


def make_store(database_path):
    return ParameterStore(database_path, TEST_KEY)


class EncryptionTests(unittest.TestCase):
    def test_loads_exactly_32_decoded_key_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "parameter-store.key"
            path.write_bytes(base64.b64encode(b"k" * 32) + b"\n")

            self.assertEqual(load_encryption_key(path), b"k" * 32)

    def test_rejects_missing_or_invalid_key_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.key"
            invalid = Path(tmp) / "invalid.key"
            invalid.write_bytes(b"not-base64")

            with self.assertRaises(EncryptionKeyError):
                load_encryption_key(missing)
            with self.assertRaises(EncryptionKeyError):
                load_encryption_key(invalid)

    def test_encrypts_and_decrypts_with_authenticated_parameter_name(self):
        cipher = ValueCipher(b"k" * 32)

        payload = cipher.encrypt("api.token", "secret-value")

        self.assertNotIn(b"secret-value", payload)
        self.assertEqual(cipher.decrypt("api.token", payload), "secret-value")
        with self.assertRaises(StorageIntegrityError):
            cipher.decrypt("other", payload)

    def test_encrypting_same_value_twice_uses_different_nonces(self):
        cipher = ValueCipher(b"k" * 32)

        first = cipher.encrypt("token", "same")
        second = cipher.encrypt("token", "same")

        self.assertNotEqual(first, second)


class ParameterStoreTests(unittest.TestCase):
    def test_put_and_get_parameter(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            store.put("region", "eu-west-2")

            self.assertEqual(store.get("region"), "eu-west-2")

    def test_put_overwrites_and_list_returns_sorted_parameters(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            store.put("zone", "b")
            store.put("account", "a")
            store.put("zone", "updated")

            items = store.list()

            self.assertEqual([item["parameter"] for item in items], ["account", "zone"])
            self.assertEqual([item["value"] for item in items], ["a", "updated"])

    def test_list_treats_wildcards_as_literal_query_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")
            store.put("plain", "one")
            store.put("other", "two")

            items = store.list("%")

            self.assertEqual(items, [])

    def test_delete_removes_parameter_and_reports_whether_it_existed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")
            store.put("temporary", "value")

            self.assertTrue(store.delete("temporary"))
            self.assertIsNone(store.get("temporary"))
            self.assertFalse(store.delete("temporary"))

    def test_rejects_invalid_parameter_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            with self.assertRaises(ParameterError):
                store.put("../unsafe", "value")

    def test_rejects_non_string_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            with self.assertRaises(ParameterError):
                store.put("region", 2)  # type: ignore[arg-type]

    def test_store_value_is_a_ciphertext_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put("password", "correct horse battery staple")

            with closing(sqlite3.connect(database_path)) as connection, connection:
                raw = connection.execute(
                    "SELECT value FROM parameters WHERE parameter = 'password'"
                ).fetchone()[0]

            self.assertIsInstance(raw, bytes)
            self.assertNotIn(b"correct horse battery staple", raw)

    def test_value_round_trips_across_store_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            make_store(database_path).put("token", "secret")

            self.assertEqual(make_store(database_path).get("token"), "secret")

    def test_wrong_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            make_store(database_path).put("token", "secret")

            with self.assertRaises(StorageIntegrityError):
                ParameterStore(database_path, b"w" * 32).get("token")

    def test_legacy_text_rows_are_encrypted_during_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "CREATE TABLE parameters (parameter TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO parameters VALUES (?, ?, ?)",
                    ("legacy", "old-value", "2026-09-11T00:00:00+00:00"),
                )

            store = make_store(database_path)

            self.assertEqual(store.get("legacy"), "old-value")
            with closing(sqlite3.connect(database_path)) as connection, connection:
                raw = connection.execute("SELECT value FROM parameters").fetchone()[0]
            self.assertIsInstance(raw, bytes)
            self.assertNotIn(b"old-value", raw)


if __name__ == "__main__":
    unittest.main()
