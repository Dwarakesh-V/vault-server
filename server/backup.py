
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

def create_backup():
    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_dir = BACKUP_DIR / "temp_backup"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir()
    
    # Copy specific files/folders to temp dir
    if DATA_DIR.exists():
        shutil.copytree(DATA_DIR, temp_dir / "data")
    if AUTH_DB.exists():
        shutil.copy(AUTH_DB, temp_dir / "auth_db.json")
        
    # Create zip from temp dir
    archive_name = BACKUP_DIR / f"backup_{timestamp}"
    shutil.make_archive(str(archive_name), 'zip', temp_dir)
    
    # Clean up temp dir
    shutil.rmtree(temp_dir)
    
    backup_zip = Path(str(archive_name) + ".zip")
    
    # Encrypt the zip file
    key = get_or_create_key()
    fernet = Fernet(key)
    
    with open(backup_zip, "rb") as f:
        data = f.read()
    
    encrypted_data = fernet.encrypt(data)
    
    encrypted_backup_path = BACKUP_DIR / f"backup_{timestamp}.enc"
    with open(encrypted_backup_path, "wb") as f:
        f.write(encrypted_data)
        
    # Remove the unencrypted zip
    os.remove(backup_zip)
    return str(encrypted_backup_path)

def restore_backup(backup_path):
    key = get_or_create_key()
    fernet = Fernet(key)
    
    with open(backup_path, "rb") as f:
        encrypted_data = f.read()
        
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        raise ValueError("Invalid key or corrupted backup")
        
    temp_zip = BACKUP_DIR / "restore_temp.zip"
    with open(temp_zip, "wb") as f:
        f.write(decrypted_data)
        
    # Clear current data
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    
    if AUTH_DB.exists():
        os.remove(AUTH_DB)
        
    # Extract
    temp_extract_dir = BACKUP_DIR / "restore_temp_dir"
    if temp_extract_dir.exists():
        shutil.rmtree(temp_extract_dir)
    temp_extract_dir.mkdir()
    
    shutil.unpack_archive(temp_zip, temp_extract_dir)
    os.remove(temp_zip)
    
    # Move files back
    if (temp_extract_dir / "data").exists():
        shutil.move(temp_extract_dir / "data", DATA_DIR)
    else:
        DATA_DIR.mkdir() # Ensure data dir exists even if empty
        
    if (temp_extract_dir / "auth_db.json").exists():
        shutil.move(temp_extract_dir / "auth_db.json", AUTH_DB)
        
    shutil.rmtree(temp_extract_dir)

def list_backups():
    if not BACKUP_DIR.exists():
        return []
    # Return list of .enc files sorted by newest first
    backups = [f.name for f in BACKUP_DIR.iterdir() if f.is_file() and f.suffix == '.enc']
    backups.sort(reverse=True)
    return backups

def get_backup_path(filename):
    # Security check: ensure filename is safe and exists
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")
    
    path = BACKUP_DIR / filename
    if not path.exists():
        raise ValueError("Backup not found")
        
    return str(path)
