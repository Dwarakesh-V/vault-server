"""
TESTS USER STORY: 5.2 (HTTPS/TLS)
Goal: Verify that the server accepts secure HTTPS connections.
"""
import requests
import urllib3

# Disable warning about self-signed certificates since we are testing locally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    print("Testing HTTPS connection to https://127.0.0.1:8000...")
    
    # Send a GET request to the secure server
    # - verify=False: Tells Python to accept our self-signed certificate (otherwise it would fail)
    response = requests.get("https://127.0.0.1:8000/", verify=False)
    
    print(f"Status Code: {response.status_code}")
    
    # Check if we got a valid response from the server
    # 200: OK
    # 404: Page not found (but server is running)
    # 401: Unauthorized (server is running but needs login)
    if response.status_code in [200, 404, 401]: 
        print("SUCCESS: HTTPS connection established.")
    else:
        print(f"Unexpected status: {response.status_code}")
        
except Exception as e:
    # If the connection fails (e.g., server not running, SSL error), print the error
    print(f"FAILURE: Could not connect to HTTPS server. Error: {e}")
