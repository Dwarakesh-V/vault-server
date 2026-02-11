
import os
import json
import shutil
import datetime
from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
AUTH_DB = BASE_DIR / "auth_db.json"
BACKUP_DIR = BASE_DIR.parent / "backups"
KEY_FILE = BASE_DIR / "secret.key"

def get_or_create_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    return key

def create_backup(username: str):
    """Create an encrypted backup of the user's vault data"""
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Source file
    user_data_file = DATA_DIR / f"{username}.json"
    if not user_data_file.exists():
        raise ValueError("No data to backup for this user")

    # Read data
    with open(user_data_file, "rb") as f:
        data = f.read()

    # Encrypt
    key = get_or_create_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    # Save backup file: backup_{username}_{timestamp}.enc
    backup_filename = f"backup_{username}_{timestamp}.enc"
    encrypted_backup_path = BACKUP_DIR / backup_filename
    
    with open(encrypted_backup_path, "wb") as f:
        f.write(encrypted_data)
        
    return str(encrypted_backup_path)

def restore_backup(backup_path: str, username: str):
    """Restore a user's vault data from backup"""
    path = Path(backup_path)
    
    # Verification: Ensure backup belongs to user
    filename = path.name
    expected_prefix = f"backup_{username}_"
    if not filename.startswith(expected_prefix):
        raise ValueError("Cannot restore backup: File does not belong to user")

    key = get_or_create_key()
    fernet = Fernet(key)
    
    with open(path, "rb") as f:
        encrypted_data = f.read()
        
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        raise ValueError("Invalid key or corrupted backup")
        
    # Verify it's valid JSON before restoring
    try:
        json.loads(decrypted_data)
    except json.JSONDecodeError:
        raise ValueError("Backup data is corrupted (invalid JSON)")

    # Restore to user's data file
    DATA_DIR.mkdir(exist_ok=True)
    user_data_file = DATA_DIR / f"{username}.json"
    
    with open(user_data_file, "wb") as f:
        f.write(decrypted_data)

def list_backups(username: str):
    """List backups for a specific user"""
    if not BACKUP_DIR.exists():
        return []
        
    backups = []
    prefix = f"backup_{username}_"
    
    for f in BACKUP_DIR.iterdir():
        if f.is_file() and f.name.startswith(prefix) and f.suffix == '.enc':
            # Parse timestamp from filename: backup_{username}_{timestamp}.enc
            timestamp = None
            try:
                # Extract timestamp part
                # filename: backup_user_20230101_120000.enc
                # Remove prefix and suffix
                ts_str = f.stem[len(prefix):] 
                dt = datetime.datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                timestamp = dt.isoformat()
            except ValueError:
                timestamp = datetime.datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                
            backups.append({
                "filename": f.name,
                "timestamp": timestamp,
                "size": f.stat().st_size
            })
            
    # Sort by filename desc (newest first)
    backups.sort(key=lambda x: x["filename"], reverse=True)
    return backups

def get_backup_path(filename):
    # Security check: ensure filename is safe and exists
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")
    
    path = BACKUP_DIR / filename
    if not path.exists():
        raise ValueError("Backup not found")
        
    return str(path)

def delete_backup(filename: str, username: str):
    """Delete a specific backup file for a user"""
    # Security check: ensure filename is safe
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")
    
    # Verify ownership
    expected_prefix = f"backup_{username}_"
    if not filename.startswith(expected_prefix):
        raise ValueError("Cannot delete backup: File does not belong to user")
        
    path = BACKUP_DIR / filename
    if not path.exists():
        raise ValueError("Backup not found")
        
    os.remove(path)
    return True
