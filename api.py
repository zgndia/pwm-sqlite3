from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import sqlite3
from cryptography.fernet import Fernet
from argon2 import PasswordHasher, exceptions
import base64
import hashlib
import os

app = FastAPI()

# --- 1. CONFIGURATION (Matched to main.py) ---
# We must use the exact same parameters as main.py, otherwise the hash 
# (and thus the derived key) will be different.
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

PEPPER = "7tQHcXzTGkDwaRWkcDd8rmDhgMvahR9w4dC3qTCtqDPp2D4DBBUqrHcWHk5YFXM4HhB8fRBMv6aWc5MvHj7SemV5xWGVVyBgbV546q2KRk5UAYZENnUkm9BvuahwpS73"
DB_PATH = "PasswordManager.db"

class LoginRequest(BaseModel):
    master_password: str

class PasswordEntry(BaseModel):
    platform: str
    username: str
    password: str

# --- 2. CRYPTO LOGIC ---
def get_key(password: str) -> bytes:
    """Derives the Fernet key using the Master Password + Hardcoded Pepper."""
    peppered_pass = (password + PEPPER).encode()
    
    # We use Argon2 to generate the raw key material
    # Note: This matches main.py logic exactly.
    raw_hash = ph.hash(peppered_pass).encode()
    
    # We use SHA256 to ensure a consistent 32-byte length for Fernet
    key_32 = hashlib.sha256(raw_hash).digest()
    fernet_key = base64.urlsafe_b64encode(key_32)
    
    # Memory management: Clean up raw bytes
    del key_32
    return fernet_key

# --- 3. API ENDPOINTS ---

@app.post("/unlock")
async def unlock_vault(req: LoginRequest):
    if not os.path.exists(DB_PATH):
         raise HTTPException(status_code=404, detail="Database file not found")

    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        row = cur.execute("SELECT masterpassword FROM master").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Vault not initialized (Run main.py to setup)")
        
        stored_hash = row[0]
        try:
            # Verify using the stored hash (which contains the salt)
            ph.verify(stored_hash.decode(), req.master_password + PEPPER)
            
            # Generate token
            token = get_key(req.master_password).decode()
            return {"status": "unlocked", "token": token}
        except exceptions.VerifyMismatchError:
            raise HTTPException(status_code=401, detail="Invalid Master Password")

@app.get("/passwords")
async def get_passwords(x_vault_token: str = Header(None, alias="x-vault-token")):
    if not x_vault_token:
        raise HTTPException(status_code=401, detail="Missing Header: x-vault-token")
    
    try:
        f = Fernet(x_vault_token.encode())
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            # Ensure the table exists
            cur.execute("CREATE TABLE IF NOT EXISTS login(platform BLOB, username BLOB, password BLOB)")
            logs = cur.execute("SELECT platform, username, password FROM login").fetchall()
            
            results = []
            for log in logs:
                results.append({
                    "platform": f.decrypt(log[0]).decode(),
                    "username": f.decrypt(log[1]).decode(),
                    "password": f.decrypt(log[2]).decode()
                })
            return results
    except Exception as e:
        # Returns 400 Bad Request if decryption fails
        print(f"Error: {e}") # Print to server console for debugging
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.post("/add")
async def add_password(entry: PasswordEntry, x_vault_token: str = Header(None, alias="x-vault-token")):
    if not x_vault_token:
        raise HTTPException(status_code=401, detail="Vault is locked")
        
    try:
        f = Fernet(x_vault_token.encode())
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            cur.execute("INSERT INTO login VALUES (?, ?, ?)", (
                f.encrypt(entry.platform.encode()), 
                f.encrypt(entry.username.encode()), 
                f.encrypt(entry.password.encode())
            ))
            con.commit()
        return {"message": "Saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Encryption failed: {str(e)}")

@app.delete("/remove/{platform_name}")
async def remove_password(platform_name: str, x_vault_token: str = Header(None, alias="x-vault-token")):
    if not x_vault_token:
        raise HTTPException(status_code=401, detail="Vault is locked")
        
    try:
        f = Fernet(x_vault_token.encode())
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            logs = cur.execute("SELECT rowid, platform FROM login").fetchall()
            
            target_rowid = None
            for rowid, enc_platform in logs:
                try:
                    decrypted_name = f.decrypt(enc_platform).decode()
                    if decrypted_name.lower() == platform_name.lower():
                        target_rowid = rowid
                        break
                except:
                    continue # Skip entries that fail to decrypt
            
            if target_rowid is None:
                raise HTTPException(status_code=404, detail="Platform not found")
            
            cur.execute("DELETE FROM login WHERE rowid = ?", (target_rowid,))
            con.commit()
            return {"message": f"Successfully deleted {platform_name}"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Delete failed: {str(e)}")