"""
Iterative backup tests — 20 test cases covering:
  CREATE          : happy-path, multiple entries, special chars, empty vault, numeric username,
                    nested blob, underscore username, large vault (100 entries)
  CREATE_NO_DATA  : user data file missing → ValueError
  RESTORE         : happy-path, multi-entry, unicode round-trip
  RESTORE_ERROR   : wrong owner → ValueError
  RESTORE_CORRUPT : tampered file → ValueError
  DELETE          : own backup → success
  DELETE_ERROR    : another user's backup → ValueError
  PATH_TRAVERSAL  : ../, \\, empty string → ValueError (Invalid filename)
  GET_PATH_MISSING: non-existent file → ValueError (Backup not found)
"""

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.backup import create_backup, delete_backup, get_backup_path, restore_backup
from tests.json_utils import load_json_with_comments


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_open_side_effect(read_handles: dict, write_handles: dict):
    """Dispatch open() calls to the correct mock handle by extension + mode."""
    def _side_effect(file, mode="r", **kwargs):
        ext = Path(str(file)).suffix.lstrip(".")
        if "r" in mode and ext in read_handles:
            return read_handles[ext](file, mode, **kwargs)
        if "w" in mode and ext in write_handles:
            return write_handles[ext](file, mode, **kwargs)
        return MagicMock()
    return _side_effect


def _build_large_blob(n: int) -> dict:
    """Generate a blob with n entries for stress testing."""
    return {f"site_{i}": f"password_{i}_!@#" for i in range(n)}


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestBackupIterative(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        data_path = Path(__file__).parent / "data" / "backup_iterative_cases.jsonc"
        cls.cases = load_json_with_comments(data_path)
        print(f"\n[ITERATIVE] Loaded {len(cls.cases)} backup test cases.")

    # ------------------------------------------------------------------
    # Shared mocks applied to all sub-tests
    # ------------------------------------------------------------------
    @patch("server.backup.Path.mkdir")
    @patch("server.backup.Path.exists")
    @patch("server.backup.get_or_create_key")
    @patch("server.backup.Fernet")
    def test_all_cases(self, mock_fernet_cls, mock_get_key, mock_exists, mock_mkdir):

        # ── crypto setup ────────────────────────────────────────────────
        mock_cipher = MagicMock()
        mock_fernet_cls.return_value = mock_cipher
        mock_cipher.encrypt.return_value = b"gAAAA_encrypted_content"
        mock_get_key.return_value = b"fake_fernet_key_32bytes_urlsafe="

        total = len(self.cases)
        for idx, case in enumerate(self.cases, start=1):
            with self.subTest(tc=idx, name=case["name"]):
                print(f"\n  [{idx:02d}/{total}] {case['name']}")
                action = case["action"]

                # Reset per-case call counts
                mock_cipher.encrypt.reset_mock()
                mock_cipher.decrypt.reset_mock()
                mock_cipher.decrypt.side_effect = None  # clear any previous error

                # ── Dispatch ─────────────────────────────────────────────
                if action == "CREATE":
                    self._run_create(case, mock_cipher, mock_exists)

                elif action == "CREATE_LARGE":
                    case = dict(case)
                    case["blob_data"] = _build_large_blob(case["entry_count"])
                    self._run_create(case, mock_cipher, mock_exists)

                elif action == "CREATE_NO_DATA":
                    self._run_create_no_data(case, mock_exists)

                elif action == "RESTORE":
                    self._run_restore(case, mock_cipher, mock_exists)

                elif action == "RESTORE_ERROR":
                    self._run_restore_error(case)

                elif action == "RESTORE_CORRUPT":
                    self._run_restore_corrupt(case, mock_cipher, mock_exists)

                elif action == "DELETE":
                    self._run_delete(case, mock_exists)

                elif action == "DELETE_ERROR":
                    self._run_delete_error(case)

                elif action == "PATH_TRAVERSAL":
                    self._run_path_traversal(case)

                elif action == "GET_PATH_MISSING":
                    self._run_get_path_missing(case, mock_exists)

                else:
                    self.fail(f"Unknown action '{action}' in TC{idx}")

                print(f"       ✅ PASSED")

        print(f"\n[ITERATIVE] All {total} test cases passed.\n")

    # ------------------------------------------------------------------
    # Action-specific helpers
    # ------------------------------------------------------------------

    def _run_create(self, case, mock_cipher, mock_exists):
        """Happy-path CREATE: encryption called, filename correct, data written."""
        user_data = json.dumps(case["blob_data"]).encode()
        mock_exists.return_value = True

        mock_src = mock_open(read_data=user_data)
        mock_dst = mock_open()
        open_se = _make_open_side_effect({"json": mock_src}, {"enc": mock_dst})

        with patch("builtins.open", side_effect=open_se):
            result_path = create_backup(case["username"])

        self.assertIn(case["expected_filename_prefix"], result_path,
                      msg=f"Filename prefix missing in: {result_path}")
        self.assertTrue(Path(result_path).name.endswith(".enc"),
                        msg=f"Expected .enc suffix, got: {result_path}")
        self.assertTrue(mock_cipher.encrypt.called,
                        msg="Fernet.encrypt() was not called")
        self.assertTrue(mock_dst().write.called,
                        msg="Encrypted data was never written to disk")

    def _run_create_no_data(self, case, mock_exists):
        """CREATE with no user data file → ValueError must be raised."""
        mock_exists.return_value = False   # user data file does NOT exist

        with self.assertRaises(ValueError) as ctx:
            create_backup(case["username"])

        self.assertIn(case["expected_error"], str(ctx.exception),
                      msg=f"Wrong error: {ctx.exception}")

    def _run_restore(self, case, mock_cipher, mock_exists):
        """Happy-path RESTORE: decryption called, correct bytes written back."""
        original_bytes = json.dumps(case["original_blob"]).encode()
        mock_cipher.decrypt.return_value = original_bytes
        mock_exists.return_value = True

        mock_src = mock_open(read_data=case["file_content"].encode())
        mock_dst = mock_open()
        open_se = _make_open_side_effect({"enc": mock_src}, {"json": mock_dst})

        with patch("builtins.open", side_effect=open_se):
            restore_backup(case["filename"], case["username"])

        self.assertTrue(mock_cipher.decrypt.called,
                        msg="Fernet.decrypt() was not called")
        self.assertTrue(mock_dst().write.called,
                        msg="Restored data was never written")
        written = mock_dst().write.call_args[0][0]
        self.assertEqual(written, original_bytes,
                         msg="Restored bytes do not match original blob")

    def _run_restore_error(self, case):
        """RESTORE with wrong-owner filename → ValueError."""
        with self.assertRaises(ValueError) as ctx:
            restore_backup(case["filename"], case["username"])
        self.assertIn(case["expected_error"], str(ctx.exception),
                      msg=f"Wrong error: {ctx.exception}")

    def _run_restore_corrupt(self, case, mock_cipher, mock_exists):
        """RESTORE with tampered/corrupt data → ValueError."""
        mock_cipher.decrypt.side_effect = Exception("Invalid token")
        mock_exists.return_value = True

        mock_src = mock_open(read_data=case["file_content"].encode())
        open_se = _make_open_side_effect({"enc": mock_src}, {})

        with patch("builtins.open", side_effect=open_se):
            with self.assertRaises(ValueError) as ctx:
                restore_backup(case["filename"], case["username"])

        self.assertIn(case["expected_error"], str(ctx.exception),
                      msg=f"Wrong error: {ctx.exception}")

    def _run_delete(self, case, mock_exists):
        """DELETE own backup → os.remove called once, no exception."""
        mock_exists.return_value = True

        with patch("server.backup.os.remove") as mock_remove:
            result = delete_backup(case["filename"], case["username"])

        self.assertTrue(result, msg="delete_backup should return True on success")
        self.assertTrue(mock_remove.called,
                        msg="os.remove() was not called for a valid delete")

    def _run_delete_error(self, case):
        """DELETE another user's backup → ValueError."""
        with self.assertRaises(ValueError) as ctx:
            delete_backup(case["filename"], case["username"])
        self.assertIn(case["expected_error"], str(ctx.exception),
                      msg=f"Wrong error: {ctx.exception}")

    def _run_path_traversal(self, case):
        """get_backup_path with dangerous filename → ValueError: Invalid filename."""
        with self.assertRaises(ValueError) as ctx:
            get_backup_path(case["filename"])
        self.assertIn(case["expected_error"], str(ctx.exception),
                      msg=f"Wrong error: {ctx.exception}")

    def _run_get_path_missing(self, case, mock_exists):
        """get_backup_path for non-existent file → ValueError: Backup not found."""
        mock_exists.return_value = False  # file does not exist

        with self.assertRaises(ValueError) as ctx:
            get_backup_path(case["filename"])
        self.assertIn(case["expected_error"], str(ctx.exception),
                      msg=f"Wrong error: {ctx.exception}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
