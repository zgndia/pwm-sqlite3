import sqlite3
import base64
import os
import hashlib
import gc
import secrets
from typing import List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from argon2 import PasswordHasher, exceptions
from cryptography.fernet import Fernet, InvalidToken
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse

# ────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'PasswordManager.db')
PEPPER_FILE = os.path.join(BASE_DIR, 'pepper.key')
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Password Manager API")
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ────────────────────────────────────────────────
# Pepper handling
# ────────────────────────────────────────────────
def load_or_create_pepper() -> str:
    if os.path.exists(PEPPER_FILE):
        with open(PEPPER_FILE, "r", encoding="utf-8") as f:
            pepper = f.read().strip()
        if len(pepper) < 64:
            raise RuntimeError("pepper.key corrupted")
        return pepper
    pepper = secrets.token_hex(64)
    with open(PEPPER_FILE, "w", encoding="utf-8") as f:
        f.write(pepper)
    if os.name != 'nt':
        os.chmod(PEPPER_FILE, 0o600)
    print("Generated new pepper.key")
    return pepper

PEPPER = load_or_create_pepper()

# ────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

def get_key(password: str) -> bytes:
    peppered = (password + PEPPER).encode()
    raw_hash = ph.hash(peppered).encode()
    key_32 = hashlib.sha256(raw_hash).digest()
    fernet_key = base64.urlsafe_b64encode(key_32)
    del raw_hash, key_32
    gc.collect()
    return fernet_key

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_master_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bytes:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        key_b64: str | None = payload.get("master_key")
        if not key_b64:
            raise HTTPException(status_code=401, detail="Invalid token")
        return base64.urlsafe_b64decode(key_b64)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Models
class UnlockRequest(BaseModel):
    password: str
class RegisterRequest(BaseModel):
    password: str
class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str
class Login(BaseModel):
    platform: str
    username: str
    password: str
class LoginResponse(BaseModel):
    platform: str
    username: str
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str

# Database
def get_db():
    con = sqlite3.connect(DB_PATH)
    try:
        yield con
    finally:
        con.close()

def initialize_database(con: sqlite3.Connection):
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS login(platform BLOB, username BLOB, password BLOB)")
    cur.execute("CREATE TABLE IF NOT EXISTS master(verification BLOB, canary BLOB)")
    con.commit()

# ────────────────────────────────────────────────
# ENDPOINTS
# ────────────────────────────────────────────────

@app.get("/status")
def vault_status(con: sqlite3.Connection = Depends(get_db)):
    initialize_database(con)
    cur = con.cursor()
    registered = cur.execute("SELECT 1 FROM master LIMIT 1").fetchone() is not None
    return {"registered": registered}

@app.post("/wipe")
def wipe_vault():
    for path in [DB_PATH, PEPPER_FILE]:
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to delete {path}")
    return {"status": "Vault completely wiped. You can now create a new one."}

@app.post("/register", response_model=Token)
def register(req: RegisterRequest, con: sqlite3.Connection = Depends(get_db)):
    initialize_database(con)
    cur = con.cursor()
    if cur.execute("SELECT 1 FROM master").fetchone():
        raise HTTPException(status_code=400, detail="Vault already exists. Use /unlock.")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password too short (min 8 chars)")
    verification = ph.hash(req.password + PEPPER)
    master_key = get_key(req.password)
    f = Fernet(master_key)
    canary = f.encrypt(b"vault_is_unlocked")
    cur.execute("INSERT INTO master VALUES (?, ?)", (verification.encode(), canary))
    con.commit()
    token = create_access_token({"master_key": base64.urlsafe_b64encode(master_key).decode()}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.post("/unlock", response_model=Token)
@limiter.limit("3/minute")
async def unlock(request: UnlockRequest, con: sqlite3.Connection = Depends(get_db)):
    initialize_database(con)
    cur = con.cursor()
    row = cur.execute("SELECT verification, canary FROM master").fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="No vault found. Create one first.")
    stored_hash, stored_canary = row
    try:
        ph.verify(stored_hash.decode(), request.password + PEPPER)
        attempt_key = get_key(request.password)
        f = Fernet(attempt_key)
        if f.decrypt(stored_canary) == b"vault_is_unlocked":
            token = create_access_token({"master_key": base64.urlsafe_b64encode(attempt_key).decode()}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            return {"access_token": token, "token_type": "bearer"}
    except (exceptions.VerifyMismatchError, InvalidToken):
        pass
    raise HTTPException(status_code=401, detail="Incorrect password.")

@app.post("/changePassword")
def change_password(
    request: ChangePasswordRequest,
    con: sqlite3.Connection = Depends(get_db),
    master_key: bytes = Depends(get_master_key)
):
    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password too short (min 8 chars).")

    cur = con.cursor()
    row = cur.execute("SELECT verification, canary FROM master").fetchone()
    if not row:
        raise HTTPException(status_code=500, detail="Master record missing — possible database corruption.")

    stored_hash, _ = row

    try:
        ph.verify(stored_hash.decode(), request.old_password + PEPPER)
    except exceptions.VerifyMismatchError:
        raise HTTPException(status_code=401, detail="Incorrect old password.")

    # New credentials
    new_verification = ph.hash(request.new_password + PEPPER)
    new_master_key = get_key(request.new_password)
    new_f = Fernet(new_master_key)
    new_canary = new_f.encrypt(b"vault_is_unlocked")

    # Re-encrypt all entries
    old_f = Fernet(master_key)
    logs = cur.execute("SELECT platform, username, password FROM login").fetchall()
    cur.execute("DELETE FROM login")

    for log in logs:
        try:
            p = old_f.decrypt(log[0]).decode()
            u = old_f.decrypt(log[1]).decode()
            pw = old_f.decrypt(log[2]).decode()
            cur.execute("INSERT INTO login VALUES (?, ?, ?)", (
                new_f.encrypt(p.encode()),
                new_f.encrypt(u.encode()),
                new_f.encrypt(pw.encode())
            ))
        except InvalidToken:
            raise HTTPException(status_code=500, detail="Decryption error during password change — possible corruption.")

    # Update master row
    cur.execute(
        "UPDATE master SET verification = ?, canary = ?",
        (new_verification.encode(), new_canary)
    )
    con.commit()
    gc.collect()

    return {"status": "password changed"}


@app.get("/logins", response_model=List[LoginResponse])
def get_logins(
    con: sqlite3.Connection = Depends(get_db),
    master_key: bytes = Depends(get_master_key)
):
    cur = con.cursor()
    f = Fernet(master_key)
    logs = cur.execute("SELECT platform, username, password FROM login").fetchall()

    result = []
    for log in logs:
        try:
            p = f.decrypt(log[0]).decode()
            u = f.decrypt(log[1]).decode()
            pw = f.decrypt(log[2]).decode()
            result.append(LoginResponse(platform=p, username=u, password=pw))
        except InvalidToken:
            raise HTTPException(status_code=401, detail="Invalid decryption key.")

    gc.collect()
    return result


@app.post("/add")
def add_login(
    login: Login,
    con: sqlite3.Connection = Depends(get_db),
    master_key: bytes = Depends(get_master_key)
):
    cur = con.cursor()
    f = Fernet(master_key)
    cur.execute("INSERT INTO login VALUES (?, ?, ?)", (
        f.encrypt(login.platform.encode()),
        f.encrypt(login.username.encode()),
        f.encrypt(login.password.encode())
    ))
    con.commit()
    gc.collect()
    return {"status": "login added"}


@app.delete("/remove")
def remove_login(
    login: Login,
    con: sqlite3.Connection = Depends(get_db),
    master_key: bytes = Depends(get_master_key)
):
    cur = con.cursor()
    f = Fernet(master_key)
    try:
        p_enc = f.encrypt(login.platform.encode())
        u_enc = f.encrypt(login.username.encode())
        pw_enc = f.encrypt(login.password.encode())

        cur.execute(
            "DELETE FROM login WHERE platform = ? AND username = ? AND password = ?",
            (p_enc, u_enc, pw_enc)
        )
        con.commit()

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Login not found.")

        return {"status": "login removed"}
    except InvalidToken:
        raise HTTPException(status_code=500, detail="Encryption error.")
    finally:
        gc.collect()
