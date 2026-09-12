import base64
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from unittest.mock import patch
from pathlib import Path

from app import (
    APIKeyError,
    ParameterConflictError,
    EncryptionKeyError,
    ParameterError,
    ParameterStore,
    StorageIntegrityError,
    ValueCipher,
    load_encryption_key,
    load_api_key,
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

    def test_loads_exactly_32_decoded_api_key_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "parameter-store-api.key"
            path.write_bytes(base64.b64encode(b"a" * 32) + b"\n")

            self.assertEqual(load_api_key(path), b"a" * 32)

    def test_rejects_missing_or_invalid_key_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.key"
            invalid = Path(tmp) / "invalid.key"
            invalid.write_bytes(b"not-base64")

            with self.assertRaises(EncryptionKeyError):
                load_encryption_key(missing)
            with self.assertRaises(EncryptionKeyError):
                load_encryption_key(invalid)

    def test_rejects_missing_invalid_and_wrong_length_api_key_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.key"
            invalid = Path(tmp) / "invalid.key"
            wrong_length = Path(tmp) / "wrong-length.key"
            invalid.write_bytes(b"not-base64")
            wrong_length.write_bytes(base64.b64encode(b"short"))

            for path in (missing, invalid, wrong_length):
                with self.subTest(path=path.name):
                    with self.assertRaises(APIKeyError):
                        load_api_key(path)

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

    def test_put_with_metadata_round_trips_tags_and_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            store.put_with_metadata(
                "db.password", "secret", ["database", "secret"], "prod"
            )

            self.assertEqual(
                store.list_metadata(),
                [
                    {
                        "parameter": "db.password",
                        "value": "secret",
                        "updated_at": store.list_metadata()[0]["updated_at"],
                        "tags": ["database", "secret"],
                        "env": "prod",
                    }
                ],
            )

    def test_plain_api_updates_preserve_existing_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")
            store.put_with_metadata("region", "old", ["location"], "prod")

            store.put("region", "new")

            item = store.list_metadata()[0]
            self.assertEqual(item["value"], "new")
            self.assertEqual(item["tags"], ["location"])
            self.assertEqual(item["env"], "prod")

    def test_update_with_metadata_renames_and_reencrypts_all_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")
            store.put_with_metadata("old.name", "old-value", ["old"], "dev")

            store.update_with_metadata(
                "old.name",
                "new.name",
                "new-value",
                ["new", "rotated"],
                "prod",
            )

            self.assertIsNone(store.get("old.name"))
            self.assertEqual(store.get("new.name"), "new-value")
            self.assertEqual(
                [(item["parameter"], item["tags"], item["env"])
                 for item in store.list_metadata()],
                [("new.name", ["new", "rotated"], "prod")],
            )

    def test_update_with_metadata_rejects_an_existing_target_without_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")
            store.put_with_metadata("source", "source-value", ["source"], "dev")
            store.put_with_metadata("target", "target-value", ["target"], "prod")

            with self.assertRaisesRegex(ParameterError, "parameter already exists"):
                store.update_with_metadata(
                    "source", "target", "replacement", ["replacement"], "test"
                )

            self.assertEqual(store.get("source"), "source-value")
            self.assertEqual(store.get("target"), "target-value")
            items = {item["parameter"]: item for item in store.list_metadata()}
            self.assertEqual(items["source"]["tags"], ["source"])
            self.assertEqual(items["source"]["env"], "dev")
            self.assertEqual(items["target"]["tags"], ["target"])
            self.assertEqual(items["target"]["env"], "prod")

    def test_rename_maps_primary_key_conflicts_to_parameter_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put_with_metadata("source", "source-value", [], "")

            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    """
                    CREATE TRIGGER create_target_before_rename
                    BEFORE UPDATE OF parameter ON parameters
                    WHEN OLD.parameter = 'source' AND NEW.parameter = 'target'
                    BEGIN
                        INSERT INTO parameters(parameter, value, updated_at)
                        VALUES ('target', X'00', 'now');
                    END
                    """
                )

            with self.assertRaises(ParameterConflictError):
                store.update_with_metadata("source", "target", "new-value", [], "")

            self.assertEqual(store.get("source"), "source-value")
            self.assertIsNone(store.get("target"))

    def test_concurrent_renames_do_not_report_two_successes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            for index in range(20):
                source = f"source{index}"
                targets = (f"one{index}", f"two{index}")
                store.put_with_metadata(source, "value", [], "")
                barrier = threading.Barrier(2)
                results = []
                results_lock = threading.Lock()

                def rename(target):
                    try:
                        barrier.wait()
                        store.update_with_metadata(source, target, target, [], "")
                    except Exception as exc:  # noqa: BLE001
                        result = (type(exc).__name__, str(exc))
                    else:
                        result = ("ok", target)
                    with results_lock:
                        results.append(result)

                threads = [threading.Thread(target=rename, args=(target,)) for target in targets]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

                self.assertEqual(
                    sorted(result[0] for result in results),
                    ["ParameterNotFoundError", "ok"],
                )
                items = store.list_metadata()
                self.assertEqual(len(items), index + 1)
                self.assertTrue(
                    {item["parameter"] for item in items}.intersection(targets)
                )

    def test_metadata_query_matches_parameter_tag_and_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")
            store.put_with_metadata("db.password", "secret", ["database"], "prod")
            store.put_with_metadata("api.url", "https://staging", ["service"], "staging")

            self.assertEqual(
                [item["parameter"] for item in store.list_metadata("DATABASE")],
                ["db.password"],
            )
            self.assertEqual(
                [item["parameter"] for item in store.list_metadata(tag="service")],
                ["api.url"],
            )
            self.assertEqual(
                [item["parameter"] for item in store.list_metadata(env="PROD")],
                ["db.password"],
            )

    def test_metadata_query_rejects_invalid_stored_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put_with_metadata("db.password", "secret", [], "prod")

            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "UPDATE parameters SET env = ? WHERE parameter = ?",
                    (sqlite3.Binary(b"prod"), "db.password"),
                )

            with self.assertRaises(StorageIntegrityError):
                store.list_metadata()

    def test_metadata_query_rejects_overlong_stored_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put_with_metadata("db.password", "secret", [], "prod")

            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "UPDATE parameters SET env = ? WHERE parameter = ?",
                    ("e" * 65, "db.password"),
                )

            with self.assertRaises(StorageIntegrityError):
                store.list_metadata()

    def test_metadata_query_rejects_deeply_nested_stored_tags_before_decoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put_with_metadata("db.password", "secret", [], "prod")
            deeply_nested_tags = "[" * 65 + "0" + "]" * 65

            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "UPDATE parameters SET tags = ? WHERE parameter = ?",
                    (deeply_nested_tags, "db.password"),
                )

            with patch("app._json.loads", side_effect=AssertionError("decoder called")):
                with self.assertRaises(StorageIntegrityError):
                    store.list_metadata()

    def test_metadata_query_rejects_deeply_nested_stored_tags(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put_with_metadata("db.password", "secret", [], "prod")
            deeply_nested_tags = "[" * 20000 + "0" + "]" * 20000

            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "UPDATE parameters SET tags = ? WHERE parameter = ?",
                    (deeply_nested_tags, "db.password"),
                )

            with self.assertRaises(StorageIntegrityError):
                store.list_metadata()

    def test_metadata_query_rejects_unencodable_stored_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            store = make_store(database_path)
            store.put_with_metadata("db.password", "secret", [], "prod")

            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "UPDATE parameters SET tags = ? WHERE parameter = ?",
                    ('["\\ud800"]', "db.password"),
                )

            with self.assertRaises(StorageIntegrityError):
                store.list_metadata()

    def test_metadata_validation_rejects_unencodable_unicode_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            with self.assertRaises(ParameterError):
                store.put_with_metadata("x", "value", ["bad\ud800"], "prod")

    def test_metadata_validation_rejects_invalid_tags_and_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = make_store(Path(tmp) / "parameters.db")

            with self.assertRaises(ParameterError):
                store.put_with_metadata("x", "value", "tag", "prod")
            with self.assertRaises(ParameterError):
                store.put_with_metadata("x", "value", [""], "prod")
            with self.assertRaises(ParameterError):
                store.put_with_metadata("x", "value", ["tag", "tag"], "prod")
            with self.assertRaises(ParameterError):
                store.put_with_metadata("x", "value", [], 7)

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
            item = store.list_metadata()[0]
            self.assertEqual(item["tags"], [])
            self.assertEqual(item["env"], "")
            with closing(sqlite3.connect(database_path)) as connection, connection:
                raw = connection.execute("SELECT value FROM parameters").fetchone()[0]
            self.assertIsInstance(raw, bytes)
            self.assertNotIn(b"old-value", raw)

    def test_existing_schema_is_migrated_with_metadata_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            database_path = Path(tmp) / "parameters.db"
            with closing(sqlite3.connect(database_path)) as connection, connection:
                connection.execute(
                    "CREATE TABLE parameters (parameter TEXT PRIMARY KEY, value BLOB NOT NULL, updated_at TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO parameters VALUES (?, ?, ?)",
                    ("legacy", ValueCipher(TEST_KEY).encrypt("legacy", "value"), "now"),
                )

            make_store(database_path)

            with closing(sqlite3.connect(database_path)) as connection:
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(parameters)")
                }
            self.assertTrue({"tags", "env"}.issubset(columns))


if __name__ == "__main__":
    unittest.main()
