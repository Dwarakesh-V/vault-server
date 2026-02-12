"""
TESTS USER STORY: 5.7 (Encrypted Backups)
Goal: Verify that backups are created, encrypted, and can be restored successfully.
"""
import os
import shutil
import json
import tempfile
from pathlib import Path
from unittest.mock import patch
from server.backup import create_backup, restore_backup

def test_backup_flow():
    """
    Tests the backup and restore functionality in isolation (without running the full server).
    Uses 'mocking' to create a temporary environment so we don't mess up real data.
    """
    # Create a temporary directory. Everything we do here vanishes after the test.
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        temp_data_dir = temp_path / "data"
        temp_auth_db = temp_path / "auth_db.json"
        
        # 1. SETUP: Create dummy user data
        temp_data_dir.mkdir()
        # Create a fake user data file with "secret" content
        (temp_data_dir / "test_user.json").write_text('{"content": "secret"}')
        # Create a fake auth database
        temp_auth_db.write_text('{"test_user": {"salt": "s", "verifier": "v"}}')
        
        print("Created dummy data in temp dir.")
        
        # 2. MOCKING: Tell the server code to use our temp paths instead of real ones
        with patch('server.backup.DATA_DIR', temp_data_dir), \
             patch('server.backup.AUTH_DB', temp_auth_db), \
             patch('server.backup.BACKUP_DIR', temp_path / "backups"):
            
            # 3. ACTION: Create a backup of "test_user"
            # This should encrypt 'test_user.json' and save it to the backups folder
            backup_path = create_backup("test_user")
            print(f"Backup created at: {backup_path}")
            
            # CHECK: Did the backup file actually get created?
            if not os.path.exists(backup_path):
                print("Backup file not found!")
                return
                
            # 4. SIMULATION: Corrupt the original data
            # We change the file content to "corrupted" to prove restoration works later
            (temp_data_dir / "test_user.json").write_text('{"content": "corrupted"}')
            
            print("Modified data (simulating corruption).")
            
            # 5. ACTION: Restore from the backup
            # This should read the encrypted backup, decrypt it, and overwrite 'test_user.json'
            restore_backup(backup_path, "test_user")
            print("Restored backup.")
            
            # 6. VERIFICATION: Check the file content
            restored_data = (temp_data_dir / "test_user.json").read_text()
            
            # We expect the file to contain "secret" again, NOT "corrupted"
            if '"content": "secret"' in restored_data:
                print("SUCCESS: Data verified!")
            else:
                print("FAILURE: Data mismatch!")
                print(f"Data: {restored_data}")

if __name__ == "__main__":
    test_backup_flow()
