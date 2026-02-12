"""
TESTS USER STORIES: 
- 5.6 (Brute Force Protection)
- 5.5 (Login Alerts)
Goal: Verify that the server limits login attempts and blocks IP after repeated failures.
"""
import requests
import time
import urllib3

# Disable warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:8000"

def test_rate_limit():
    """
    Simulates a Brute Force attack by trying to log in multiple times with wrong credentials.
    Verifies that the server blocks the IP after the 5th failed attempt.
    """
    print(f"Testing rate limit against {BASE_URL}...")
    
    # Generate a unique username to avoid conflicts with previous tests
    username = f"attacker_{int(time.time())}"
    
    # We loop 7 times to exceed the limit of 5 failed attempts.
    # Expected behavior:
    # - Attempts 1 to 5: Server returns 401 (Unauthorized) - indicates wrong password.
    # - Attempt 6+: Server returns 429 (Too Many Requests) - indicates IP is blocked.
    
    for i in range(1, 8):
        print(f"\nAttempt {i}: Logging in with invalid credentials...")
        try:
            # Send POST request to /login
            # json payload contains the username and a WRONG password verifier
            resp = requests.post(
                f"{BASE_URL}/login", 
                json={"username": username, "verifier": "wrong_password_verifier"},
                verify=False # Ignore the self-signed certificate warning
            )
            
            print(f"Status Code: {resp.status_code}")
            
            # CHECK: Did we get blocked?
            if resp.status_code == 429:
                print("SUCCESS: Received 429 Too Many Requests!")
                print("Response Body:", resp.text) # Should show the "IP blocked" message
                return
            
            # CHECK: Was it just a normal failed login?
            elif resp.status_code == 401:
                print("Received 401 (Expected for failed login)")
            
            # If we get anything else (like 500 error), something is wrong
            else:
                print(f"Unexpected status: {resp.status_code}")
                
        except Exception as e:
            print(f"Request failed: {e}")
            
    # If the loop finishes without receiving a 429, the test failed
    print("\nFAILURE: Did not receive 429 after 5 attempts.")

if __name__ == "__main__":
    test_rate_limit()
