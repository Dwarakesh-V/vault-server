
import os
import sys
import json
from pathlib import Path

# Add project root to path so we can import server modules
sys.path.append(str(Path(__file__).resolve().parent))

try:
    from server.audit import log_action, get_logs, LOG_FILE
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def verify_log_encryption():
    print("=" * 60)
    print("Verifying Audit Log Encryption (User Story 5.12)")
    print("=" * 60)
    
    test_user = f"encrypt_test_{os.urandom(4).hex()}"
    test_action = "ENCRYPTION_VERIFY"
    test_details = "Testing if logs are encrypted at rest."
    
    print(f"Adding test log entry for user: {test_user}")
    log_action(test_user, test_action, test_details)
    
    # 1. Check if the file exists and is not empty
    if not LOG_FILE.exists():
        print("FAILURE: Log file was not created.")
        return False
    
    # 2. Directly read the file to see if it's plaintext JSON
    print("Reading raw file content...")
    with open(LOG_FILE, "rb") as f:
        raw_content = f.read()
    
    try:
        # If this succeeds, it's plaintext JSON (or valid UTF-8 JSON)
        parsed = json.loads(raw_content.decode())
        print("FAILURE: Log file is stored in plaintext JSON!")
        return False
    except (json.JSONDecodeError, UnicodeDecodeError):
        print("SUCCESS: Log file is NOT plaintext JSON (appears encrypted).")
    
    # 3. Use the audit module to read it back
    print("Reading back logs via audit module...")
    logs = get_logs(test_user)
    
    if len(logs) == 0:
        print("FAILURE: Could not retrieve logs via audit module.")
        return False
    
    latest_log = logs[0]
    if latest_log["action"] == test_action and latest_log["details"] == test_details:
        print("SUCCESS: Logs decrypted and retrieved correctly.")
        print(f"Retrieved: {latest_log['timestamp']} | {latest_log['action']} | {latest_log['details']}")
    else:
        print(f"FAILURE: Log content mismatch. Expected {test_action}, got {latest_log['action']}")
        return False

    print("\nALL ENCRYPTION VERIFICATION TESTS PASSED!")
    return True

if __name__ == "__main__":
    if verify_log_encryption():
        sys.exit(0)
    else:
        sys.exit(1)
