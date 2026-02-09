
import os
import shutil
from pathlib import Path
from server.backup import create_backup, restore_backup, DATA_DIR, AUTH_DB

def test_backup_flow():
    # Setup dummy data
    DATA_DIR.mkdir(exist_ok=True)
    (DATA_DIR / "test_user.json").write_text('{"content": "secret"}')
    AUTH_DB.write_text('{"test_user": {"salt": "s", "verifier": "v"}}')
    
    print("Created dummy data.")
    
    # Create backup
    backup_path = create_backup()
    print(f"Backup created at: {backup_path}")
    
    # Verify backup exists
    if not os.path.exists(backup_path):
        print("Backup file not found!")
        return
        
    # Modify data
    (DATA_DIR / "test_user.json").write_text('{"content": "corrupted"}')
    AUTH_DB.write_text('{}')
    print("Modified data (simulating corruption).")
    
    # Restore
    restore_backup(backup_path)
    print("Restored backup.")
    
    # Verify restoration
    restored_data = (DATA_DIR / "test_user.json").read_text()
    restored_auth = AUTH_DB.read_text()
    
    if '"content": "secret"' in restored_data and '"test_user"' in restored_auth:
        print("SUCCESS: Data verified!")
    else:
        print("FAILURE: Data mismatch!")
        print(f"Data: {restored_data}")
        print(f"Auth: {restored_auth}")

if __name__ == "__main__":
    test_backup_flow()
