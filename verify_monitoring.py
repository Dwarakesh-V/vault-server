
import os
import sys
from pathlib import Path

# Add project root to path so we can import server modules
sys.path.append(str(Path(__file__).resolve().parent))

try:
    from server.security import SecurityManager
    from server.audit import get_logs, LOG_FILE
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

def test_configurable_thresholds():
    print("Testing configurable thresholds...")
    os.environ["VAULT_MAX_LOGIN_ATTEMPTS"] = "3"
    os.environ["VAULT_BLOCK_DURATION_SECONDS"] = "10"
    
    sm = SecurityManager()
    assert sm.MAX_ATTEMPTS == 3
    assert sm.BLOCK_DURATION == 10
    print("PASSED: Thresholds effectively loaded from environment.")

def test_alert_logging():
    print("Testing alert logging to audit log...")
    # Clear log file for clean test
    if LOG_FILE.exists():
        LOG_FILE.unlink()
    
    sm = SecurityManager()
    sm.MAX_ATTEMPTS = 2
    
    ip = "1.2.3.4"
    target_user = "test_target"
    
    # First failure
    sm.record_failed_attempt(ip, target_user)
    
    # Second failure - should trigger block
    sm.record_failed_attempt(ip, target_user)
    
    assert ip in sm.blocked_ips
    
    # Verify audit logs
    system_logs = get_logs("SYSTEM")
    user_logs = get_logs(target_user)
    
    # Check for SECURITY_BLOCK in SYSTEM logs
    block_found = any(log["action"] == "SECURITY_BLOCK" and ip in log["details"] for log in system_logs)
    assert block_found, "SECURITY_BLOCK not found in SYSTEM logs"
    
    # Check for SECURITY_SUSPICIOUS in user logs
    suspicious_found = any(log["action"] == "SECURITY_SUSPICIOUS" and target_user in log["details"] for log in user_logs)
    assert suspicious_found, f"SECURITY_SUSPICIOUS not found in logs for user {target_user}"
    
    print("PASSED: Security alerts successfully recorded in audit logs.")

if __name__ == "__main__":
    try:
        test_configurable_thresholds()
        test_alert_logging()
        print("\nALL MONITORING TESTS PASSED!")
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
    except Exception as e:
        print(f"\nAN ERROR OCCURRED: {e}")
