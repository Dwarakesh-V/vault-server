
import os
import shutil
import datetime
from pathlib import Path

# Mocking the environment
BACKUP_DIR = Path("mock_backups")
if BACKUP_DIR.exists():
    shutil.rmtree(BACKUP_DIR)
BACKUP_DIR.mkdir(exist_ok=True)

def list_backups_new(username: str):
    backups = []
    for f in BACKUP_DIR.iterdir():
        if not f.is_file() or f.suffix != '.enc':
            continue

        filename = f.name
        if not filename.startswith("backup_"):
            continue
            
        expected_start = f"backup_{username}_"
        if not filename.startswith(expected_start):
            continue
            
        remaining = filename[len(expected_start):]
        if not (remaining and remaining[0].isdigit()):
            continue

        timestamp = None
        try:
            ts_str = Path(remaining).stem
            for fmt in ("%Y%m%d_%H%M%S_%f", "%Y%m%d_%H%M%S"):
                try:
                    dt = datetime.datetime.strptime(ts_str, fmt)
                    break
                except ValueError:
                    continue
            else:
                dt = datetime.datetime.fromtimestamp(f.stat().st_mtime)
            timestamp = dt.isoformat()
        except Exception:
            timestamp = datetime.datetime.fromtimestamp(f.stat().st_mtime).isoformat()

        backups.append({
            "filename":  filename,
            "timestamp": timestamp,
            "size":      f.stat().st_size
        })

    backups.sort(key=lambda x: x["filename"], reverse=True)
    return backups

# Test Case 1: mahi vs mahitha
(BACKUP_DIR / "backup_mahitha_20260222_120000.enc").touch()
(BACKUP_DIR / "backup_mahi_20260222_110000.enc").touch()

print("Test Case 1: Prefix collision check (mahi vs mahitha)")
mahi_backups = [b['filename'] for b in list_backups_new('mahi')]
mahitha_backups = [b['filename'] for b in list_backups_new('mahitha')]
print(f"Backups for 'mahi': {mahi_backups}")
print(f"Backups for 'mahitha': {mahitha_backups}")

assert "backup_mahitha_20260222_120000.enc" not in mahi_backups, "FAILED: mahi saw mahitha's backup!"
assert "backup_mahi_20260222_110000.enc" not in mahitha_backups, "FAILED: mahitha saw mahi's backup!"
print("PASSED: mahi and mahitha are isolated.")

# Test Case 2: user vs user1
(BACKUP_DIR / "backup_user1_20260222_150000.enc").touch()
(BACKUP_DIR / "backup_user_20260222_140000.enc").touch()

print("\nTest Case 2: Prefix collision check (user vs user1)")
user_backups = [b['filename'] for b in list_backups_new('user')]
user1_backups = [b['filename'] for b in list_backups_new('user1')]
print(f"Backups for 'user': {user_backups}")
print(f"Backups for 'user1': {user1_backups}")

assert "backup_user1_20260222_150000.enc" not in user_backups, "FAILED: user saw user1's backup!"
print("PASSED: user and user1 are isolated.")

# cleanup
shutil.rmtree(BACKUP_DIR)
