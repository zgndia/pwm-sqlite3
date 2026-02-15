from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
from cryptography.fernet import Fernet
from argon2 import PasswordHasher, exceptions
import base64
import hashlib

app = FastAPI()
ph = PasswordHasher()
PEPPER = "7tQHcXzTGkDwaRWkcDd8rmDhgMvahR9w4dC3qTCtqDPp2D4DBBUqrHcWHk5YFXM4HhB8fRBMv6aWc5MvHj7SemV5xWGVVyBgbV546q2KRk5UAYZENnUkm9BvuahwpS73"
DB_PATH = "PasswordManager.db"

class LoginRequest(BaseModel):
    master_password: str

class PasswordEntry(BaseModel):
    platform: str
    username: str
    password: str

# Get Encryption Key
def get_key(password: str) -> bytes:
    peppered_pass = (password + PEPPER).encode()
    raw_hash = ph.hash(peppered_pass).encode()
    key_32 = hashlib.sha256(raw_hash).digest()
    return base64.urlsafe_b64encode(key_32)

@app.post("/unlock")
async def unlock_vault(req: LoginRequest):
    """Verifies master password and returns the encryption key as a temporary token."""
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        row = cur.execute("SELECT masterpassword, salt FROM master").fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Vault not initialized")
        
        stored_hash, stored_canary = row
        try:
            ph.verify(stored_hash.decode(), req.master_password + PEPPER)
            # If valid, return the derived key. 
            # Note: Store this in a secure server-side session/cache.
            token = get_key(req.master_password).decode()
            return {"status": "unlocked", "token": token}
        except exceptions.VerifyMismatchError:
            raise HTTPException(status_code=401, detail="Invalid Master Password")

@app.get("/passwords")
async def get_passwords(x_vault_token: str = Header(None)):
    """Decrypts and returns all logins using the token provided in the header."""
    if not x_vault_token:
        raise HTTPException(status_code=401, detail="Vault is locked")
    
    try:
        f = Fernet(x_vault_token.encode())
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            logs = cur.execute("SELECT platform, username, password FROM login").fetchall()
            
            results = []
            for log in logs:
                results.append({
                    "platform": f.decrypt(log[0]).decode(),
                    "username": f.decrypt(log[1]).decode(),
                    "password": f.decrypt(log[2]).decode()
                })
            return results
    except Exception:
        raise HTTPException(status_code=400, detail="Session expired or invalid token")

@app.post("/add")
async def add_password(entry: PasswordEntry, x_vault_token: str = Header(None)):
    """Encrypts and saves a new login."""
    if not x_vault_token:
        raise HTTPException(status_code=401, detail="Vault is locked")
        
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

@app.delete("/remove/{platform_name}")
async def remove_password(platform_name: str, x_vault_token: str = Header(None)):
    """Decrypts entries to find a match for platform_name and deletes it."""
    if not x_vault_token:
        raise HTTPException(status_code=401, detail="Vault is locked")
        
    try:
        f = Fernet(x_vault_token.encode())
        with sqlite3.connect(DB_PATH) as con:
            cur = con.cursor()
            # Fetch all encrypted rows
            logs = cur.execute("SELECT rowid, platform FROM login").fetchall()
            
            target_rowid = None
            for rowid, enc_platform in logs:
                decrypted_name = f.decrypt(enc_platform).decode()
                # Case-insensitive match
                if decrypted_name.lower() == platform_name.lower():
                    target_rowid = rowid
                    break
            
            if target_rowid is None:
                raise HTTPException(status_code=404, detail="Platform not found")
            
            # Delete by the unique rowid
            cur.execute("DELETE FROM login WHERE rowid = ?", (target_rowid,))
            con.commit()
            
            return {"message": f"Successfully deleted {platform_name}"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail="Error during deletion")