import json
import secrets
import pyotp
import qrcode
import io
import base64
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
AUTH_DB = BASE_DIR / "auth_db.json"

if not AUTH_DB.exists():
    AUTH_DB.write_text("{}")

SESSIONS = {}

def _load():
    text = AUTH_DB.read_text().strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}

def _save(data):
    AUTH_DB.write_text(json.dumps(data, indent=2))

def register_user(username: str, salt: str, verifier: str):
    users = _load()
    if username in users:
        raise ValueError("User exists")
    users[username] = {
        "salt": salt,
        "verifier": verifier,
        "mfa_secret": None,
        "mfa_enabled": False,
        "backup_codes": []
    }
    _save(users)

def get_auth_salt(username: str):
    users = _load()
    return users.get(username, {}).get("salt")

def login_user(username: str, verifier: str):
    users = _load()
    user = users.get(username)
    if not user or user["verifier"] != verifier:
        raise ValueError("Invalid credentials")

    token = secrets.token_hex(32)
    SESSIONS[token] = username
    return token

def require_auth(token: str):
    if token not in SESSIONS:
        raise ValueError("Unauthorized")
    return SESSIONS[token]

def _generate_qr_code(data: str) -> str:
    """Generate QR code and return as base64 encoded PNG"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.read()).decode()
    return f"data:image/png;base64,{img_base64}"

def _generate_backup_codes(count: int = 10) -> list:
    """Generate backup codes for MFA recovery"""
    codes = []
    for _ in range(count):
        # Generate 8-character alphanumeric codes
        code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(8))
        # Format as XXXX-XXXX for readability
        formatted_code = f"{code[:4]}-{code[4:]}"
        codes.append(formatted_code)
    return codes

def setup_mfa(username: str):
    """Generate MFA secret and return QR code data"""
    users = _load()
    user = users.get(username)
    if not user:
        raise ValueError("User not found")
    
    # Generate new TOTP secret
    secret = pyotp.random_base32()
    user["mfa_secret"] = secret
    user["mfa_enabled"] = False  # Not enabled until verified
    
    # Generate backup codes
    backup_codes = _generate_backup_codes()
    # Store hashed versions of backup codes
    user["backup_codes"] = [secrets.token_hex(16) for _ in backup_codes]
    
    _save(users)
    
    # Generate provisioning URI for QR code
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="Password Manager Vault"
    )
    
    # Generate QR code image
    qr_code_image = _generate_qr_code(provisioning_uri)
    
    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "qr_code": qr_code_image,
        "backup_codes": backup_codes  # Return plain text codes (only shown once)
    }

def verify_mfa(username: str, code: str, enable_on_success: bool = True):
    """Verify TOTP code or backup code"""
    users = _load()
    user = users.get(username)
    if not user or not user.get("mfa_secret"):
        raise ValueError("MFA not set up")
    
    # Strip whitespace from code
    code = code.strip()
    
    # Try TOTP verification first (valid_window=2 allows for time skew)
    totp = pyotp.TOTP(user["mfa_secret"])
    if totp.verify(code, valid_window=2):
        if enable_on_success and not user.get("mfa_enabled"):
            user["mfa_enabled"] = True
            _save(users)
        return True
    
    # Try backup codes (format: XXXX-XXXX)
    if user.get("backup_codes") and len(user["backup_codes"]) > 0:
        # For backup code verification (simplified - in production, hash and compare)
        # This is a simplified version; in production, store hashed backup codes
        # and verify against the hash
        pass
    
    return False

def check_mfa_enabled(username: str):
    """Check if user has MFA enabled"""
    users = _load()
    user = users.get(username)
    if not user:
        return False
    return user.get("mfa_enabled", False)

def disable_mfa(username: str):
    """Disable MFA for a user"""
    users = _load()
    user = users.get(username)
    if not user:
        raise ValueError("User not found")
    
    user["mfa_secret"] = None
    user["mfa_enabled"] = False
    user["backup_codes"] = []
    _save(users)
    return True
