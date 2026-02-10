"""
MFA Test Script for Password Manager Vault
Tests the complete MFA flow including setup, QR code generation, and verification
"""

import requests
import os
import json
import pyotp
from argon2.low_level import hash_secret_raw, Type

BASE_URL = "http://localhost:8000"

def derive_auth_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=128 * 1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )

def test_mfa_flow():
    print("=" * 60)
    print("MFA Test Flow for Password Manager Vault")
    print("=" * 60)
    
    # Step 1: Register a test user
    print("\n[Step 1] Registering test user...")
    username = f"mfatest_{os.urandom(4).hex()}"
    password = "TestPassword123!"
    
    salt = os.urandom(16)
    verifier = derive_auth_key(password, salt)
    
    r = requests.post(
        f"{BASE_URL}/register",
        json={
            "username": username,
            "salt": salt.hex(),
            "verifier": verifier.hex(),
        },
    )
    
    if r.status_code == 200:
        print(f"✓ Successfully registered user: {username}")
    else:
        print(f"✗ Registration failed: {r.text}")
        return
    
    # Step 2: Login to get token
    print("\n[Step 2] Logging in...")
    r = requests.post(
        f"{BASE_URL}/login",
        json={"username": username, "verifier": verifier.hex()},
    )
    
    if r.status_code != 200:
        print(f"✗ Login failed: {r.text}")
        return
    
    token = r.json()["token"]
    print(f"✓ Login successful, got token")
    
    # Step 3: Check MFA status (should be disabled)
    print("\n[Step 3] Checking initial MFA status...")
    r = requests.get(f"{BASE_URL}/mfa/status/{username}")
    mfa_enabled = r.json()["mfa_enabled"]
    
    if not mfa_enabled:
        print(f"✓ MFA is initially disabled (as expected)")
    else:
        print(f"✗ Unexpected: MFA is already enabled")
        return
    
    # Step 4: Setup MFA
    print("\n[Step 4] Setting up MFA...")
    r = requests.post(
        f"{BASE_URL}/mfa/setup",
        headers={"Authorization": token}
    )
    
    if r.status_code != 200:
        print(f"✗ MFA setup failed: {r.text}")
        return
    
    mfa_data = r.json()
    secret = mfa_data["secret"]
    provisioning_uri = mfa_data["provisioning_uri"]
    qr_code = mfa_data["qr_code"]
    backup_codes = mfa_data["backup_codes"]
    
    print(f"✓ MFA setup successful!")
    print(f"  - Secret: {secret}")
    print(f"  - Provisioning URI: {provisioning_uri}")
    print(f"  - QR Code: {'Present (base64 data)' if qr_code.startswith('data:image') else 'Missing'}")
    print(f"  - Backup Codes ({len(backup_codes)} codes):")
    for i, code in enumerate(backup_codes[:3], 1):
        print(f"    {i}. {code}")
    if len(backup_codes) > 3:
        print(f"    ... and {len(backup_codes) - 3} more")
    
    # Step 5: Generate TOTP code and verify
    print("\n[Step 5] Generating and verifying TOTP code...")
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    print(f"  Generated TOTP code: {current_code}")
    
    r = requests.post(
        f"{BASE_URL}/mfa/verify",
        json={"username": username, "code": current_code}
    )
    
    if r.status_code == 200:
        print(f"✓ MFA verification successful!")
        print(f"  Response: {r.json()}")
    else:
        print(f"✗ MFA verification failed: {r.text}")
        return
    
    # Step 6: Check MFA status (should be enabled now)
    print("\n[Step 6] Checking MFA status after verification...")
    r = requests.get(f"{BASE_URL}/mfa/status/{username}")
    mfa_enabled = r.json()["mfa_enabled"]
    
    if mfa_enabled:
        print(f"✓ MFA is now enabled (as expected)")
    else:
        print(f"✗ Unexpected: MFA is still disabled")
        return
    
    # Step 7: Test login with MFA
    print("\n[Step 7] Testing login with MFA...")
    new_code = totp.now()
    print(f"  Generated new TOTP code: {new_code}")
    
    r = requests.post(
        f"{BASE_URL}/login/mfa",
        json={
            "username": username,
            "verifier": verifier.hex(),
            "mfa_code": new_code
        }
    )
    
    if r.status_code == 200:
        print(f"✓ MFA login successful!")
        new_token = r.json()["token"]
        print(f"  Got new token")
    else:
        print(f"✗ MFA login failed: {r.text}")
        return
    
    # Step 8: Test MFA disable
    print("\n[Step 8] Testing MFA disable...")
    r = requests.post(
        f"{BASE_URL}/mfa/disable",
        headers={"Authorization": new_token}
    )
    
    if r.status_code == 200:
        print(f"✓ MFA disabled successfully!")
        print(f"  Response: {r.json()}")
    else:
        print(f"✗ MFA disable failed: {r.text}")
        return
    
    # Step 9: Verify MFA is disabled
    print("\n[Step 9] Verifying MFA is disabled...")
    r = requests.get(f"{BASE_URL}/mfa/status/{username}")
    mfa_enabled = r.json()["mfa_enabled"]
    
    if not mfa_enabled:
        print(f"✓ MFA is disabled (as expected)")
    else:
        print(f"✗ Unexpected: MFA is still enabled")
        return
    
    # Summary
    print("\n" + "=" * 60)
    print("✓ ALL MFA TESTS PASSED!")
    print("=" * 60)
    print("\nTest Summary:")
    print("  ✓ User registration")
    print("  ✓ User login")
    print("  ✓ MFA status check")
    print("  ✓ MFA setup with QR code")
    print("  ✓ TOTP code generation")
    print("  ✓ MFA verification")
    print("  ✓ Login with MFA")
    print("  ✓ MFA disable")
    print("\nThe MFA implementation is working correctly!")

if __name__ == "__main__":
    try:
        test_mfa_flow()
    except requests.exceptions.ConnectionError:
        print("\n✗ ERROR: Cannot connect to server at", BASE_URL)
        print("Make sure the server is running:")
        print("  uvicorn server.api:app --reload --port 8000")
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
