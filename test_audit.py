"""
TESTS USER STORIES:
- 5.4 (Monitoring/Logging)
- 5.11 (Audit Logs)
Goal: Verify that user actions (Register, Login, Vault operations) are recorded in the audit log.
"""
import requests
import os
import json
import time
import urllib3

# Suppress SSL warnings since we are using self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:8000"

def test_audit_logs():
    """
    Performs a sequence of actions: Register -> Login -> Access Vault -> Update Vault.
    Then fetches the audit logs and checks if all these actions were recorded.
    """
    print("=" * 60)
    print("Audit Log Test Flow")
    print("=" * 60)
    
    # 1. SETUP: Create a random user for this test
    username = f"audittest_{os.urandom(4).hex()}"
    password = "TestPassword123!"
    
    # 2. ACTION: Register the new user
    print(f"Registering user: {username}")
    try:
        r = requests.post(
            f"{BASE_URL}/register",
            json={
                "username": username,
                "salt": "dummy_salt",
                "verifier": "dummy_verifier",
            },
            verify=False
        )
        if r.status_code != 200:
            print(f"Registration failed: {r.text}")
            return
    except Exception as e:
        print(f"Registration request failed: {e}")
        return

    # 3. ACTION: Login to get the access token
    print("Logging in...")
    try:
        r = requests.post(
            f"{BASE_URL}/login",
            json={"username": username, "verifier": "dummy_verifier"},
            verify=False
        )
        if r.status_code != 200:
            print(f"Login failed: {r.text}")
            return
        token = r.json()["token"] # Store token for subsequent requests
    except Exception as e:
        print(f"Login request failed: {e}")
        return

    # 4. ACTIONS: Perform vault operations to trigger more logs
    print("Performing actions...")
    
    # Action A: User accesses their vault (Expected log: VAULT_ACCESS)
    try:
        requests.get(
            f"{BASE_URL}/vault", 
            headers={"Authorization": token}, # Authenticate using the token
            verify=False
        )
        
        # Action B: User updates their vault (Expected log: VAULT_UPDATE)
        requests.post(
            f"{BASE_URL}/vault", 
            headers={"Authorization": token},
            json={"blob": {"entries": []}}, # Sending empty vault data
            verify=False
        )
    except Exception as e:
        print(f"Vault action failed: {e}")
        return
    
    # Wait briefly to ensure file I/O operations complete on the server
    time.sleep(1)
    
    # 5. VERIFICATION: Fetch the audit logs
    print("Fetching logs...")
    try:
        r = requests.get(
            f"{BASE_URL}/logs", 
            headers={"Authorization": token},
            verify=False
        )
        if r.status_code != 200:
            print(f"Failed to fetch logs: {r.text}")
            return
            
        logs = r.json()["logs"]
        print(f"\nRetrieved {len(logs)} log entries:")
        
        # We expect these 4 specific action types to verify the feature works
        expected_actions = ["REGISTER", "LOGIN", "VAULT_ACCESS", "VAULT_UPDATE"]
        found_actions = []
        
        for log in logs:
            # Print each log to show what was recorded
            print(f"- {log['timestamp']} | {log['action']} | {log['details']}")
            found_actions.append(log['action'])
            
        # Check if any expected action is missing from the logs we retrieved
        missing = [action for action in expected_actions if action not in found_actions]
        
        if not missing:
            print("\nSUCCESS: All expected actions were logged.")
        else:
            print(f"\nFAILURE: Missing log entries for: {missing}")
            
    except Exception as e:
        print(f"Log fetch failed: {e}")

if __name__ == "__main__":
    test_audit_logs()
