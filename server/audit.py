
import json
import threading
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet
from server.backup import get_or_create_key  # reuse the same server key

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "audit_log.json"

# Thread lock to prevent concurrent writes/reads from corrupting the log file
_log_lock = threading.Lock()

def _get_cipher():
    """Return a Fernet cipher using the server's shared secret key."""
    return Fernet(get_or_create_key())

def _ensure_log_file():
    """Create an empty encrypted log file if it doesn't exist."""
    if not LOG_FILE.exists():
        DATA_DIR.mkdir(exist_ok=True)
        # Store an empty list [] in encrypted form
        cipher = _get_cipher()
        encrypted_data = cipher.encrypt(json.dumps([]).encode())
        with open(LOG_FILE, "wb") as f:
            f.write(encrypted_data)

def _read_logs_decrypted():
    """Read and decrypt the log file, falling back to plaintext for migration."""
    if not LOG_FILE.exists():
        return []
        
    with open(LOG_FILE, "rb") as f:
        raw_data = f.read()
        
    if not raw_data:
        return []

    # Try to decrypt
    try:
        cipher = _get_cipher()
        decrypted_data = cipher.decrypt(raw_data)
        return json.loads(decrypted_data)
    except Exception:
        # If decryption fails, it might be legacy plaintext JSON
        try:
            return json.loads(raw_data.decode())
        except json.JSONDecodeError:
            print("Warning: Audit log file is corrupted or unreadable.")
            return []

def log_action(username: str, action: str, details: str = None):
    _ensure_log_file()
    
    timestamp = datetime.now().isoformat()
    entry = {
        "timestamp": timestamp,
        "username": username,
        "action": action,
        "details": details or ""
    }
    
    try:
        with _log_lock:
            logs = _read_logs_decrypted()
            logs.append(entry)
            
            # Encrypt and write back
            cipher = _get_cipher()
            encrypted_data = cipher.encrypt(json.dumps(logs, indent=2).encode())
            with open(LOG_FILE, "wb") as f:
                f.write(encrypted_data)
                
    except Exception as e:
        print(f"Error writing audit log: {e}")

def get_logs(username: str):
    _ensure_log_file()
    
    try:
        with _log_lock:
            all_logs = _read_logs_decrypted()
            
        # Filter logs for the specific user
        user_logs = [log for log in all_logs if log["username"] == username]
        
        # Sort by timestamp descending
        user_logs.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return user_logs
    except Exception as e:
        print(f"Error reading audit log: {e}")
        return []
