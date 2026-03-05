
import os
import shutil
from pathlib import Path

# Mocking the environment
BACKUP_DIR = Path("mock_backups")
BACKUP_DIR.mkdir(exist_ok=True)

def list_backups(username: str):
    prefix = f"backup_{username}_"
    backups = []
    for f in BACKUP_DIR.iterdir():
        if f.is_file() and f.name.startswith(prefix) and f.name.endswith(".enc"):
            backups.append(f.name)
    return backups

# Test Case: mahi vs mahitha
(BACKUP_DIR / "backup_mahitha_20260222_120000.enc").touch()
(BACKUP_DIR / "backup_mahi_20260222_110000.enc").touch()

print(f"Backups for 'mahitha': {list_backups('mahitha')}")
print(f"Backups for 'mahi': {list_backups('mahi')}")

# cleanup
shutil.rmtree(BACKUP_DIR)
