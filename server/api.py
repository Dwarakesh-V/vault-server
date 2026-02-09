from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from pathlib import Path
from server.auth import (
    register_user,
    login_user,
    get_auth_salt,
    require_auth,
)
from server.storage import store_blob, load_blob
from server.backup import create_backup, restore_backup, list_backups, get_backup_path

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
        register_user(req.username.lower(), req.salt, req.verifier)
        return {"ok": True}
    except ValueError:
        raise HTTPException(400, "User exists")

@app.post("/login")
def login(req: LoginReq):
    try:
        token = login_user(req.username.lower(), req.verifier)
        return {"token": token}
    except ValueError:
        raise HTTPException(401, "Invalid credentials")

@app.get("/vault")
def get_vault(authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    return {"blob": load_blob(user)}

@app.post("/vault")
def put_vault(req: VaultReq, authorization: str = Header()):
    try:
        user = require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    store_blob(user, req.blob)
    return {"ok": True}

class RestoreReq(BaseModel):
    filename: str

@app.get("/backups")
def get_backups(authorization: str = Header()):
    try:
        require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    return {"backups": list_backups()}

@app.post("/backups")
def create_new_backup(authorization: str = Header()):
    try:
        require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    path = create_backup()
    return {"filename": Path(path).name}

@app.post("/backups/restore")
def restore_backup_endpoint(req: RestoreReq, authorization: str = Header()):
    try:
        require_auth(authorization)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    
    try:
        path = get_backup_path(req.filename)
        restore_backup(path)
    except ValueError as e:
        raise HTTPException(400, str(e))
        
    return {"ok": True}
