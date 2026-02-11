
import requests
import time

BASE_URL = "https://127.0.0.1:8000"
# Disable warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

def test_rate_limiting():
    print(f"Testing rate limiting on {BASE_URL}...")
    
    # login endpoint
    url = f"{BASE_URL}/login"
    data = {"username": "attacker", "verifier": "wrong_password"}
    
    print("Simulating brute force attack...")
    for i in range(1, 7):
        try:
            response = requests.post(url, json=data, verify=False)
            print(f"Attempt {i}: Status {response.status_code}")
            
            if response.status_code == 429:
                print("SUCCESS: Blocked with 429 Too Many Requests!")
                print(f"Server response: {response.json()}")
                return True
                
        except Exception as e:
            print(f"Error: {e}")
            return False
            
    print("FAILURE: Did not get blocked after 6 attempts.")
    return False

if __name__ == "__main__":
    test_rate_limiting()
