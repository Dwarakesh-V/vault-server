from fastapi import FastAPI, Header, HTTPException, Request
from server.security import security_manager   # shared rate-limiter / brute-force blocker
from pydantic import BaseModel
from pathlib import Path

# ── Auth helpers ───────────────────────────────────────────────────────────────
from server.auth import (
    register_user,       # create a new user account
    login_user,          # validate credentials and issue a session token
    get_auth_salt,       # return the client-side salt needed to derive the verifier
    require_auth,        # parse & validate an Authorization header token
    setup_mfa,           # generate a TOTP secret + QR code for a user
    verify_mfa,          # check a 6-digit TOTP code and enable MFA
    check_mfa_enabled,   # return True/False whether MFA is active for a user
    disable_mfa,         # turn off MFA for a user
)

from server.storage import store_blob, load_blob   # encrypted vault blob I/O
from server.backup import (                         # encrypted backup management
    create_backup,
    restore_backup,
    list_backups,
    get_backup_path,
    delete_backup,
)
from server.audit import log_action, get_logs       # audit trail for security events

# ── Application instance ───────────────────────────────────────────────────────
app = FastAPI()


# ══════════════════════════════════════════════════════════════════════════════
# Request body models (Pydantic validates these automatically on every request)
# ══════════════════════════════════════════════════════════════════════════════

class RegisterReq(BaseModel):
    """Body for POST /register — all fields required."""
    username: str   # chosen username (lowercased before storage)
    salt: str       # client-generated random salt for password hashing
    verifier: str   # SRP/Argon2 verifier derived from (password + salt) client-side

class LoginReq(BaseModel):
    """Body for POST /login — standard login without MFA."""
    username: str
    verifier: str   # re-derived verifier; server compares it to the stored one

class VaultReq(BaseModel):
    """Body for POST /vault — stores the encrypted vault blob."""
    blob: dict      # fully encrypted on the client; server never sees plaintext

class MFAVerifyReq(BaseModel):
    """Body for POST /mfa/verify — activate MFA after scanning the QR code."""
    username: str
    code: str       # 6-digit TOTP code from the authenticator app

class MFALoginReq(BaseModel):
    """Body for POST /login/mfa — login requiring both password AND MFA code."""
    username: str
    verifier: str   # password verifier (same as LoginReq)
    mfa_code: str   # 6-digit TOTP code for the MFA second factor

class RestoreReq(BaseModel):
    """Body for POST /backups/restore — specifies which backup to restore."""
    filename: str   # bare filename only (e.g. backup_alice_20260221_080000_123456.enc)


# ══════════════════════════════════════════════════════════════════════════════
# Authentication endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/auth_salt/{username}")
def auth_salt(username: str):
    """
    Return the stored salt for a user so the client can re-derive the
    password verifier before logging in.

    The client needs this salt to run the same KDF (Argon2/PBKDF2) that
    was used during registration and produce a matching verifier.
    """
    username = username.lower()   # normalise case to match stored value
    salt = get_auth_salt(username)

    # If the username doesn't exist in the database, return 404
    if not salt:
        raise HTTPException(404, "User not found")

    return {"salt": salt}


@app.post("/register")
def register(req: RegisterReq, request: Request):
    """
    Register a new user account.

    The server stores only the salt and the verifier — never the raw password.
    If the IP has been rate-limited (too many failed attempts) the registration
    is also blocked to prevent account-creation spam from the same IP.
    """
    client_ip = request.client.host   # extract the caller's IP for rate-limit tracking

    try:
        register_user(req.username.lower(), req.salt, req.verifier)
        return {"ok": True}

    except ValueError as e:
        # If the IP is blocked, return 429 Too Many Requests with the wait time
        if "IP blocked" in str(e):
            raise HTTPException(429, str(e))

        # Any other ValueError means the username is already taken → 400
        raise HTTPException(400, "User exists")


@app.post("/login")
def login(req: LoginReq, request: Request):
    """
    Standard login (no MFA).

    Flow:
      1. Check if the caller's IP is currently rate-limited (blocked).
      2. Validate the password verifier against the stored one.
      3. On success: clear the IP's failure counter and return a session token.
      4. On failure: record the failed attempt (may trigger a block) and return 401.
    """
    client_ip = request.client.host

    try:
        # Step 1 — Reject immediately if this IP is already blocked
        security_manager.check_rate_limit(client_ip)

        # Step 2 — Attempt to authenticate; raises ValueError on bad credentials
        token = login_user(req.username.lower(), req.verifier)

        # Step 3 — Successful login: reset the failure counter for this IP
        security_manager.reset_attempts(client_ip)
        return {"token": token}

    except ValueError as e:
        # If check_rate_limit raised the block error, surface it as HTTP 429
        if "IP blocked" in str(e):
            raise HTTPException(429, str(e))

        # Wrong password → count this as a failed attempt against the IP
        if "Invalid credentials" in str(e):
            security_manager.record_failed_attempt(client_ip, req.username)

        # Always return a generic 401 (never reveal which part was wrong)
        raise HTTPException(401, "Invalid credentials")


# ══════════════════════════════════════════════════════════════════════════════
# Vault endpoints  (require a valid session token in the Authorization header)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/vault")
def get_vault(authorization: str = Header()):
    """
    Retrieve the authenticated user's encrypted vault blob.

    The blob was encrypted client-side before being stored, so the server
    returns raw ciphertext — it never sees the plaintext passwords.
    """
    try:
        # Validate the token and resolve it to the username
        user = require_auth(authorization)
    except ValueError:
        # Token missing, expired, or invalid → reject with 401
        raise HTTPException(401, "Unauthorized")

    # Record this access in the audit log for security traceability
    log_action(user, "VAULT_ACCESS", "Vault retrieved")
    return {"blob": load_blob(user)}


@app.post("/vault")
def put_vault(req: VaultReq, authorization: str = Header()):
    """
    Store (overwrite) the authenticated user's encrypted vault blob.

    The client always sends the full encrypted blob; partial updates are not
    supported to keep the server logic simple and the data consistent.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    # Persist the encrypted blob to disk
    store_blob(user, req.blob)

    # Audit trail entry — logs that the vault was updated (not what was in it)
    log_action(user, "VAULT_UPDATE", "Vault updated")
    return {"ok": True}


# ══════════════════════════════════════════════════════════════════════════════
# MFA (Multi-Factor Authentication) endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/mfa/setup")
def mfa_setup(authorization: str = Header()):
    """
    Initiate MFA setup for the authenticated user.

    Returns a TOTP provisioning URI, a base64-encoded QR code image, and
    a set of one-time backup codes.  The client must scan the QR code with
    an authenticator app and then call /mfa/verify to activate MFA.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    try:
        # Generate the TOTP secret, QR code, and backup codes for this user
        mfa_data = setup_mfa(user)
        log_action(user, "MFA_SETUP_INIT", "MFA setup initiated")
        return mfa_data
    except ValueError as e:
        # e.g. MFA already enabled — return descriptive error
        raise HTTPException(400, str(e))


@app.post("/mfa/verify")
def mfa_verify(req: MFAVerifyReq, request: Request):
    """
    Verify a TOTP code entered by the user after scanning the QR code.

    On success, MFA is enabled for the account.
    This endpoint is also rate-limited: if the IP is blocked, return 429.
    """
    client_ip = request.client.host

    try:
        # Validate the 6-digit TOTP code (strip whitespace to avoid typos)
        is_valid = verify_mfa(req.username.lower(), req.code.strip())

        if is_valid:
            # Code matched → MFA is now active for this user
            return {"ok": True, "message": "MFA enabled successfully"}
        else:
            # Code did not match (wrong digits / expired window)
            raise HTTPException(400, "Invalid MFA code")

    except ValueError as e:
        # If the IP was blocked (too many wrong MFA codes), surface 429
        if "IP blocked" in str(e):
            raise HTTPException(429, str(e))
        raise HTTPException(400, str(e))


@app.post("/login/mfa")
def login_with_mfa(req: MFALoginReq, request: Request):
    """
    Two-factor login: password verifier + TOTP code, both must be correct.

    Flow:
      1. Check if the IP is rate-limited (block excessive attempts).
      2. Validate the password verifier first.
      3. Then validate the MFA code.
      4. Return the session token only if BOTH checks pass.

    Separating the two checks means a wrong password still counts as a
    failed attempt against the IP, protecting both factors independently.
    """
    client_ip = request.client.host
    username  = req.username.lower()

    # Step 1 — Reject the request immediately if this IP is currently blocked
    try:
        security_manager.check_rate_limit(client_ip)
    except ValueError as e:
        if "IP blocked" in str(e):
            raise HTTPException(429, str(e))
        raise   # re-raise any unexpected error

    # Step 2 — Validate the password verifier
    try:
        token = login_user(username, req.verifier)
    except ValueError:
        # Wrong password → count as a failed attempt and return 401
        security_manager.record_failed_attempt(client_ip, username)
        raise HTTPException(401, "Invalid username or password")

    # Step 3 — Validate the TOTP code (enable_on_success=False → don't re-enable MFA)
    try:
        is_valid = verify_mfa(username, req.mfa_code.strip(), enable_on_success=False)

        if not is_valid:
            # Wrong MFA code → reject (don't return the token)
            raise HTTPException(401, "Invalid MFA code")

        # Both factors verified → return the session token
        return {"token": token}

    except ValueError as e:
        # User tried to log in with MFA but hasn't set it up yet
        if "MFA not set up" in str(e):
            raise HTTPException(400, "MFA not enabled for this user")

        # Safety net: catch any late-arriving IP-block error from verify_mfa
        if "IP blocked" in str(e):
            raise HTTPException(429, str(e))

        raise HTTPException(401, "MFA verification failed")


@app.get("/mfa/status/{username}")
def mfa_status(username: str):
    """
    Return whether MFA is currently enabled for the given username.

    Used by the Flutter client to decide which login form to show
    (standard login vs. login-with-MFA).  No authentication required —
    this is public information (knowing MFA is enabled doesn't help an attacker).
    """
    username = username.lower()
    enabled  = check_mfa_enabled(username)
    return {"mfa_enabled": enabled}


@app.post("/mfa/disable")
def mfa_disable(authorization: str = Header()):
    """
    Disable MFA for the authenticated user.

    Requires a valid session token — the user must already be logged in
    before they can turn off their second factor.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    try:
        disable_mfa(user)
        log_action(user, "MFA_DISABLED", "MFA disabled")
        return {"ok": True, "message": "MFA disabled successfully"}
    except ValueError as e:
        # e.g. MFA was not enabled in the first place
        raise HTTPException(400, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Backup endpoints  (all require a valid session token)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/backups")
def get_backups(authorization: str = Header()):
    """
    List all encrypted backup files that belong to the authenticated user,
    sorted newest-first.

    Returns a list of objects: [{filename, timestamp, size}, …]
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    log_action(user, "BACKUP_LIST", "Listed backups")
    return {"backups": list_backups(user)}


@app.post("/backups")
def create_new_backup(authorization: str = Header()):
    """
    Create a new encrypted backup of the authenticated user's current vault.

    The vault data is read from disk, encrypted with AES (Fernet), and saved
    as a .enc file in the backups directory.  The filename includes a
    microsecond-precision timestamp to prevent collisions on rapid clicks.

    Returns the bare filename of the newly created backup.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    try:
        # create_backup returns the full path; extract just the filename for the response
        path     = create_backup(user)
        filename = Path(path).name

        log_action(user, "BACKUP_CREATE", f"Created backup: {filename}")
        return {"filename": filename}

    except ValueError as e:
        # e.g. user has no vault data to back up yet
        raise HTTPException(400, str(e))


@app.post("/backups/restore")
def restore_backup_endpoint(req: RestoreReq, authorization: str = Header()):
    """
    Restore the authenticated user's vault from a previously created backup.

    Steps performed by restore_backup():
      1. Verify the backup file belongs to this user (filename prefix check).
      2. Decrypt the backup with the server's Fernet key.
      3. Validate the decrypted content is valid JSON.
      4. Overwrite the user's live vault file with the decrypted data.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    try:
        # Safely resolve the filename to a full path (rejects path traversal)
        path = get_backup_path(req.filename)

        # Decrypt and restore the backup to the user's live vault file
        restore_backup(path, user)

        log_action(user, "BACKUP_RESTORE", f"Restored backup: {req.filename}")

    except ValueError as e:
        # e.g. wrong owner, corrupted backup, file not found, or invalid filename
        raise HTTPException(400, str(e))

    return {"ok": True}


@app.delete("/backups/{filename}")
def delete_backup_endpoint(filename: str, authorization: str = Header()):
    """
    Permanently delete a backup file.

    The filename is extracted from the URL path (e.g. /backups/backup_alice_…enc).
    delete_backup() performs sanitisation and ownership checks before removal.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    try:
        # Validate ownership and delete the file (raises ValueError on any violation)
        delete_backup(filename, user)
        log_action(user, "BACKUP_DELETE", f"Deleted backup: {filename}")
        return {"ok": True, "message": "Backup deleted successfully"}

    except ValueError as e:
        # e.g. file belongs to another user, path traversal attempt, or file missing
        raise HTTPException(400, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Audit log endpoint
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/logs")
def get_audit_logs(authorization: str = Header()):
    """
    Return the audit log entries for the authenticated user, newest-first.

    Each entry contains: timestamp, username, action, details.
    Sensitive values (passwords, tokens) are never written to the audit log.
    """
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")

    return {"logs": get_logs(user)}
