
import os
import json
import shutil
import datetime
import threading
from pathlib import Path
from cryptography.fernet import Fernet

# ── Directory & file paths resolved relative to this file's location ──────────
BASE_DIR = Path(__file__).resolve().parent       # → server/
DATA_DIR = BASE_DIR / "data"                     # → server/data/ (live vault blobs)
AUTH_DB  = BASE_DIR / "auth_db.json"             # → server/auth_db.json (user credentials)
BACKUP_DIR = BASE_DIR.parent / "backups"         # → vault-server/backups/ (encrypted backup files)
KEY_FILE   = BASE_DIR / "secret.key"             # → server/secret.key (Fernet symmetric key)

# Thread lock used to prevent a race condition where two concurrent requests
# both check that secret.key doesn't exist and then both try to create it,
# resulting in two different keys being written.
_key_lock = threading.Lock()


def get_or_create_key():
    """
    Return the Fernet symmetric encryption key, creating it if it doesn't
    exist yet.

    The lock ensures that even under concurrent requests only one thread
    ever writes the key file.  All subsequent calls simply read and return
    the existing bytes.
    """
    with _key_lock:                    # acquire lock → only one thread enters at a time
        if KEY_FILE.exists():          # if the key file already exists on disk …
            return KEY_FILE.read_bytes()   # … just read and return it

        # Key file not found → generate a brand-new random Fernet key
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)      # persist it so future server restarts reuse the same key
        return key


def create_backup(username: str):
    """
    Create an encrypted backup of the given user's vault data file and
    save it to the backups directory.

    Steps:
      1. Ensure the backup directory exists.
      2. Build a unique filename using the current timestamp (microsecond precision).
      3. Read the user's live vault JSON from DATA_DIR.
      4. Encrypt the raw bytes with Fernet (AES-128-CBC + HMAC-SHA256).
      5. Write the ciphertext to the backup file.

    Returns the full string path of the created backup file.
    Raises ValueError if the user has no vault data to back up.
    """
    # Create the backups directory if it doesn't already exist (no error if it does)
    BACKUP_DIR.mkdir(exist_ok=True)

    # Use microsecond-precision timestamp so rapid back-to-back clicks never
    # produce the same filename (old format used only seconds → collision risk)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    # Build the path to the user's live vault data file
    user_data_file = DATA_DIR / f"{username}.json"

    # If the user has never saved any vault data, there is nothing to back up
    if not user_data_file.exists():
        raise ValueError("No data to backup for this user")

    # Read the vault data as raw bytes (preserves encoding exactly)
    with open(user_data_file, "rb") as f:
        data = f.read()

    # Load (or create) the symmetric key, then initialise the Fernet cipher
    key    = get_or_create_key()
    fernet = Fernet(key)

    # Encrypt the raw vault bytes → produces an authenticated ciphertext token
    encrypted_data = fernet.encrypt(data)

    # Build the backup filename: backup_{username}_{timestamp}.enc
    backup_filename     = f"backup_{username}_{timestamp}.enc"
    encrypted_backup_path = BACKUP_DIR / backup_filename

    # Write the encrypted bytes to the backup file
    with open(encrypted_backup_path, "wb") as f:
        f.write(encrypted_data)

    # Return the full path so the API can extract and return the filename
    return str(encrypted_backup_path)


def restore_backup(backup_path: str, username: str):
    """
    Restore a user's vault data from an encrypted backup file.

    Steps:
      1. Verify the backup file actually belongs to the requesting user
         (filename must start with backup_{username}_).
      2. Read and decrypt the backup file.
      3. Validate the decrypted bytes are valid JSON before overwriting live data.
      4. Write the decrypted bytes back to the user's live vault file.

    Raises ValueError for ownership violations, decryption failures, or
    JSON corruption.
    """
    # Wrap the string path in a Path object for convenient manipulation
    path = Path(backup_path)

    # ── Ownership check ────────────────────────────────────────────────────────
    filename        = path.name
    expected_prefix = f"backup_{username}_"

    # If the filename doesn't start with backup_{username}_, the file belongs
    # to a different user — reject immediately to prevent cross-user data access
    if not filename.startswith(expected_prefix):
        raise ValueError("Cannot restore backup: File does not belong to user")

    # Load the symmetric key and create the cipher
    key    = get_or_create_key()
    fernet = Fernet(key)

    # Read the encrypted backup bytes from disk
    with open(path, "rb") as f:
        encrypted_data = f.read()

    # ── Decryption ─────────────────────────────────────────────────────────────
    try:
        # Fernet.decrypt() also verifies the HMAC — any tampering raises an exception
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        # Catch all Fernet errors (wrong key, bit-flipping, truncation, …)
        raise ValueError("Invalid key or corrupted backup")

    # ── JSON validation ────────────────────────────────────────────────────────
    try:
        # Parse JSON to confirm the decrypted content is structurally valid
        # before we overwrite the user's live data with potentially corrupt bytes
        json.loads(decrypted_data)
    except json.JSONDecodeError:
        raise ValueError("Backup data is corrupted (invalid JSON)")

    # ── Restore ────────────────────────────────────────────────────────────────
    # Ensure the data directory exists (might be absent in a fresh install)
    DATA_DIR.mkdir(exist_ok=True)

    # Resolve the path to the user's live vault file
    user_data_file = DATA_DIR / f"{username}.json"

    # Overwrite the live vault with the decrypted backup bytes
    with open(user_data_file, "wb") as f:
        f.write(decrypted_data)


def list_backups(username: str):
    """
    Return a list of all backup files that belong to the given user,
    sorted newest-first.

    Each item in the returned list is a dict with:
      - filename  : the bare filename (e.g. backup_alice_20260221_080000_123456.enc)
      - timestamp : ISO-8601 string parsed from the filename (or file mtime as fallback)
      - size      : file size in bytes

    Returns an empty list if the backup directory doesn't exist yet.
    """
    # If the backup directory has never been created there are no backups to list
    if not BACKUP_DIR.exists():
        return []

    backups = []                          # accumulator for matching backup entries
    prefix  = f"backup_{username}_"       # every backup for this user starts with this

    # ── Scan every entry in the backup directory ───────────────────────────────
    for f in BACKUP_DIR.iterdir():        # iterate over all files & subdirs in backups/

        # Only process files (skip subdirectories) whose name matches the user's
        # prefix AND whose extension is .enc (encrypted backups only)
        if f.is_file() and f.name.startswith(prefix) and f.suffix == '.enc':

            # ── Timestamp parsing ──────────────────────────────────────────────
            timestamp = None
            try:
                # Strip the prefix and the .enc suffix to isolate the timestamp string
                # e.g. "backup_alice_20260221_080000_123456.enc"
                #       stem → "backup_alice_20260221_080000_123456"
                #       after strip → "20260221_080000_123456"
                ts_str = f.stem[len(prefix):]

                # Try both timestamp formats:
                #   New format (microseconds): %Y%m%d_%H%M%S_%f  e.g. 20260221_080000_123456
                #   Old format (no micros)   : %Y%m%d_%H%M%S     e.g. 20260221_080000
                for fmt in ("%Y%m%d_%H%M%S_%f", "%Y%m%d_%H%M%S"):
                    try:
                        dt = datetime.datetime.strptime(ts_str, fmt)
                        break          # successfully parsed → stop trying formats
                    except ValueError:
                        continue       # this format didn't match → try the next one
                else:
                    # The for-loop completed without a break → neither format matched
                    raise ValueError("Unknown timestamp format")

                timestamp = dt.isoformat()   # convert to ISO-8601 string for the API

            except ValueError:
                # Fallback: if the filename timestamp can't be parsed, use the
                # file's last-modified time from the OS filesystem metadata
                timestamp = datetime.datetime.fromtimestamp(f.stat().st_mtime).isoformat()

            # Append this backup's metadata to the result list
            backups.append({
                "filename":  f.name,
                "timestamp": timestamp,
                "size":      f.stat().st_size   # size in bytes
            })

    # Sort the list by filename in descending order so the newest backup appears first
    # (filename contains the timestamp so lexicographic order == chronological order)
    backups.sort(key=lambda x: x["filename"], reverse=True)
    return backups


def get_backup_path(filename):
    """
    Validate a backup filename and return its full absolute path as a string.

    Security checks performed:
      - Rejects empty / falsy filenames.
      - Rejects filenames containing '..' (directory traversal via parent refs).
      - Rejects filenames containing '/' or '\\' (path separator injection).

    Raises ValueError if the filename is unsafe or if the file doesn't exist.
    """
    # ── Input sanitisation ─────────────────────────────────────────────────────
    # Reject if: empty string, contains '..', contains '/', or contains '\'
    # Any of these could allow an attacker to escape the backups directory
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")

    # Build the full path inside the backup directory
    path = BACKUP_DIR / filename

    # If the file doesn't exist on disk, there's nothing to return
    if not path.exists():
        raise ValueError("Backup not found")

    return str(path)


def delete_backup(filename: str, username: str):
    """
    Permanently delete a backup file after verifying it belongs to the
    requesting user.

    Steps:
      1. Sanitise the filename (same checks as get_backup_path).
      2. Confirm the file's naming prefix matches the user.
      3. Confirm the file exists.
      4. Delete it from disk.

    Returns True on success.
    Raises ValueError for invalid filenames, ownership violations, or
    missing files.
    """
    # ── Input sanitisation ─────────────────────────────────────────────────────
    # Same path-traversal guards as get_backup_path: reject empty, '..', '/', '\'
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")

    # ── Ownership check ────────────────────────────────────────────────────────
    expected_prefix = f"backup_{username}_"

    # If the filename doesn't start with backup_{username}_, it belongs to
    # a different user — reject to prevent cross-user deletion
    if not filename.startswith(expected_prefix):
        raise ValueError("Cannot delete backup: File does not belong to user")

    # Build the full path and confirm the file is actually on disk
    path = BACKUP_DIR / filename

    # Guard against a race condition where the file was already deleted
    # by another request between the ownership check and the removal
    if not path.exists():
        raise ValueError("Backup not found")

    # Remove the file from the filesystem permanently
    os.remove(path)
    return True
