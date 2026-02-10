from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from pathlib import Path
from server.auth import (
    register_user,
    login_user,
    get_auth_salt,
    require_auth,
    setup_mfa,
    verify_mfa,
    check_mfa_enabled,
    disable_mfa,
)
from server.storage import store_blob, load_blob
from server.backup import create_backup, restore_backup, list_backups, get_backup_path
from server.audit import log_action, get_logs

app = FastAPI()

class RegisterReq(BaseModel):
    username: str
    salt: str
    verifier: str

class LoginReq(BaseModel):
    username: str
    verifier: str

class VaultReq(BaseModel):
    blob: dict

class MFAVerifyReq(BaseModel):
    username: str
    code: str

class MFALoginReq(BaseModel):
    username: str
    verifier: str
    mfa_code: str

class RestoreReq(BaseModel):
    filename: str

@app.get("/auth_salt/{username}")
def auth_salt(username: str):
    username = username.lower()
    salt = get_auth_salt(username)
    if not salt:
        raise HTTPException(404, "User not found")
    return {"salt": salt}

@app.post("/register")
def register(req: RegisterReq):
    try:
        username = req.username.lower()
        register_user(username, req.salt, req.verifier)
        log_action(username, "REGISTER", "User registered")
        return {"ok": True}
    except ValueError:
        raise HTTPException(400, "User exists")

@app.post("/login")
def login(req: LoginReq):
    try:
        username = req.username.lower()
        token = login_user(username, req.verifier)
        log_action(username, "LOGIN", "User logged in")
        return {"token": token}
    except ValueError:
        # We can't log easily if login fails as we don't have a trusted user, but we could try
        raise HTTPException(401, "Invalid credentials")

@app.get("/vault")
def get_vault(authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    
    log_action(user, "VAULT_ACCESS", "Vault retrieved")
    return {"blob": load_blob(user)}

@app.post("/vault")
def put_vault(req: VaultReq, authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    store_blob(user, req.blob)
    log_action(user, "VAULT_UPDATE", "Vault updated")
    return {"ok": True}

@app.post("/mfa/setup")
def mfa_setup(authorization: str = Header()):
    """Setup MFA for authenticated user - returns QR code data"""
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    
    try:
        mfa_data = setup_mfa(user)
        log_action(user, "MFA_SETUP_INIT", "MFA setup initiated")
        return mfa_data
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.post("/mfa/verify")
def mfa_verify(req: MFAVerifyReq):
    """Verify MFA code and enable MFA for user"""
    try:
        username = req.username.lower()
        is_valid = verify_mfa(username, req.code.strip())
        if is_valid:
            log_action(username, "MFA_ENABLED", "MFA verified and enabled")
            return {"ok": True, "message": "MFA enabled successfully"}
        else:
            log_action(username, "MFA_VERIFY_FAIL", "MFA verification failed")
            raise HTTPException(400, "Invalid MFA code")
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.post("/login/mfa")
def login_with_mfa(req: MFALoginReq):
    """Login with username, password, and MFA code"""
    username = req.username.lower()
    try:
        # First verify password
        token = login_user(username, req.verifier)
    except ValueError:
        raise HTTPException(401, "Invalid username or password")
    
    try:
        # Then verify MFA code
        is_valid = verify_mfa(username, req.mfa_code.strip(), enable_on_success=False)
        if not is_valid:
            log_action(username, "LOGIN_MFA_FAIL", "MFA code invalid during login")
            raise HTTPException(401, "Invalid MFA code")
        
        log_action(username, "LOGIN_MFA_SUCCESS", "Logged in with MFA")
        return {"token": token}
    except ValueError as e:
        if "MFA not set up" in str(e):
            raise HTTPException(400, "MFA not enabled for this user")
        raise HTTPException(401, "MFA verification failed")

@app.get("/mfa/status/{username}")
def mfa_status(username: str):
    """Check if user has MFA enabled"""
    username = username.lower()
    enabled = check_mfa_enabled(username)
    return {"mfa_enabled": enabled}

@app.post("/mfa/disable")
def mfa_disable(authorization: str = Header()):
    """Disable MFA for authenticated user"""
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    
    try:
        disable_mfa(user)
        log_action(user, "MFA_DISABLED", "MFA disabled")
        return {"ok": True, "message": "MFA disabled successfully"}
    except ValueError as e:
        raise HTTPException(400, str(e))

@app.get("/backups")
def get_backups(authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    log_action(user, "BACKUP_LIST", "Listed backups")
    return {"backups": list_backups()}

@app.post("/backups")
def create_new_backup(authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    path = create_backup()
    filename = Path(path).name
    log_action(user, "BACKUP_CREATE", f"Created backup: {filename}")
    return {"filename": filename}

@app.post("/backups/restore")
def restore_backup_endpoint(req: RestoreReq, authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    
    try:
        path = get_backup_path(req.filename)
        restore_backup(path)
        log_action(user, "BACKUP_RESTORE", f"Restored backup: {req.filename}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    
    return {"ok": True}

@app.get("/logs")
def get_audit_logs(authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    
    return {"logs": get_logs(user)}
