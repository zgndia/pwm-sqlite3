import sqlite3
import base64
import os
import sys
import gc
import secrets
import hashlib
from os import system
from difflib import SequenceMatcher
from typing import Optional
from argon2 import PasswordHasher, exceptions
from cryptography.fernet import Fernet, InvalidToken

# ────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'PasswordManager.db')
PEPPER_FILE = os.path.join(BASE_DIR, 'pepper.key')
PACNAME = "pwm"

MASTER_KEY: Optional[bytes] = None

# ────────────────────────────────────────────────
# Pepper (persistent, generated once)
# ────────────────────────────────────────────────
def load_or_create_pepper() -> str:
    if os.path.exists(PEPPER_FILE):
        with open(PEPPER_FILE, "r", encoding="utf-8") as f:
            pepper = f.read().strip()
        if len(pepper) < 64:
            raise RuntimeError("pepper.key file is corrupted (too short)")
        return pepper

    pepper = secrets.token_hex(64)
    try:
        with open(PEPPER_FILE, "w", encoding="utf-8") as f:
            f.write(pepper)
        if os.name != 'nt':
            os.chmod(PEPPER_FILE, 0o600)
    except Exception as exc:
        raise RuntimeError(f"Failed to create {PEPPER_FILE}: {exc}")

    print(f"Generated new pepper and saved to {PEPPER_FILE}")
    return pepper

PEPPER = load_or_create_pepper()

# ────────────────────────────────────────────────
# Crypto setup
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

# ────────────────────────────────────────────────
# Masked input (cross-platform)
# ────────────────────────────────────────────────
def get_masked_input(prompt: str = "") -> str:
    print(prompt, end="", flush=True)
    password = ""
    while True:
        if os.name == 'nt':
            import msvcrt
            char = msvcrt.getch().decode('utf-8', errors='ignore')
        else:
            import tty, termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                char = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        if char in ('\x03', '\x04'):  # Ctrl+C / Ctrl+D
            print("^C")
            raise KeyboardInterrupt

        if char in ('\r', '\n'):
            print()
            break
        elif char in ('\x08', '\x7f'):  # Backspace
            if password:
                password = password[:-1]
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        else:
            password += char
            sys.stdout.write('*')
            sys.stdout.flush()

    return password

# ────────────────────────────────────────────────
# Database helpers
# ────────────────────────────────────────────────
def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)

def initialize_database(con: sqlite3.Connection):
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS login(platform BLOB, username BLOB, password BLOB)")
    cur.execute("CREATE TABLE IF NOT EXISTS master(verification BLOB, canary BLOB)")
    con.commit()

# ────────────────────────────────────────────────
# Authentication
# ────────────────────────────────────────────────
def ask_for_master_pass(mode: str = "login") -> None:
    global MASTER_KEY
    con = get_connection()
    cur = con.cursor()

    while True:
        if mode == "register":
            try:
                mpass = get_masked_input("Pick a master password (min 8 chars): ")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                sys.exit(0)

            if len(mpass) < 8:
                print("Password must be at least 8 characters.")
                continue
            
            try:
                re_enter = get_masked_input("Re-enter your master password: ")
            except KeyboardInterrupt:
                print("\nOperation cancelled.")
                sys.exit(0)
            
            if re_enter != mpass:
                print("The passwords don't match.")
                continue

            conf = input("Confirm this is your master password? [Y/n]: ").strip().lower()
            if conf not in ('', 'y', 'yes'):
                print("Cancelled.")
                continue

            verification = ph.hash(mpass + PEPPER)
            key = get_key(mpass)
            f = Fernet(key)
            canary = f.encrypt(b"vault_is_unlocked")

            cur.execute("INSERT INTO master VALUES (?, ?)", (verification.encode(), canary))
            con.commit()
            MASTER_KEY = key
            print("Master password registered.")
            mpass = None
            break

        else:  # login
            try:
                mpass = get_masked_input("Enter master password: ")
            except KeyboardInterrupt:
                print("\nGoodbye.")
                sys.exit(0)

            row = cur.execute("SELECT verification, canary FROM master").fetchone()
            if not row:
                print("No master password set. Run in register mode or use --register.")
                sys.exit(1)

            stored_hash, stored_canary = row

            try:
                ph.verify(stored_hash.decode(), mpass + PEPPER)
                attempt_key = get_key(mpass)
                f = Fernet(attempt_key)
                if f.decrypt(stored_canary) == b"vault_is_unlocked":
                    MASTER_KEY = attempt_key
                    print("Access granted.")
                    mpass = None
                    gc.collect()
                    break
            except (exceptions.VerifyMismatchError, InvalidToken):
                print("Incorrect password.")

    con.close()

# ────────────────────────────────────────────────
# CRUD
# ────────────────────────────────────────────────
def insert_login(platform: str, username: str, password: str) -> None:
    if MASTER_KEY is None:
        raise RuntimeError("Not unlocked")
    con = get_connection()
    cur = con.cursor()
    f = Fernet(MASTER_KEY)
    cur.execute("INSERT INTO login VALUES (?, ?, ?)", (
        f.encrypt(platform.encode()),
        f.encrypt(username.encode()),
        f.encrypt(password.encode())
    ))
    con.commit()
    con.close()
    gc.collect()

def delete_login(p_enc: bytes, u_enc: bytes, pw_enc: bytes) -> bool:
    con = get_connection()
    cur = con.cursor()
    cur.execute("DELETE FROM login WHERE platform = ? AND username = ? AND password = ?",
                (p_enc, u_enc, pw_enc))
    changed = cur.rowcount > 0
    con.commit()
    con.close()
    gc.collect()
    return changed

# ────────────────────────────────────────────────
# UI commands
# ────────────────────────────────────────────────
def help_menu():
    print(f"\n--- {PACNAME.upper()} HELP ---")
    print("Commands:")
    print("  add          Add a new login")
    print("  logs / logins  List all stored logins")
    print("  rm           Remove a login (fuzzy search)")
    print("  clear        Clear the screen")
    print("  exit / quit  Exit the program")
    print("  help / h     Show this help")

def show_logins():
    if MASTER_KEY is None:
        print("Vault is locked.")
        return
    con = get_connection()
    cur = con.cursor()
    f = Fernet(MASTER_KEY)
    rows = cur.execute("SELECT platform, username, password FROM login").fetchall()
    con.close()

    if not rows:
        print("No logins saved yet.")
        return

    print(f"\n--- {PACNAME.upper()} STORED LOGINS ---")
    for row in rows:
        try:
            p = f.decrypt(row[0]).decode()
            u = f.decrypt(row[1]).decode()
            pw = f.decrypt(row[2]).decode()
            print(f"  [{p:20}]  user: {u:25}  pass: {pw}")
        except InvalidToken:
            print("  [Decryption failed — possible corruption]")
    gc.collect()

def add_login():
    if MASTER_KEY is None:
        print("Vault is locked.")
        return

    p = input("Platform / service: ").strip()
    u = input("Username / email:   ").strip()
    pw = get_masked_input("Password:           ")

    print("\nYou entered:")
    print(f"  Platform: {p}")
    print(f"  Username: {u}")
    print(f"  Password: {'*' * len(pw)}")

    if input("Save? [Y/n]: ").strip().lower() not in ('', 'y', 'yes'):
        print("Cancelled.")
        return

    insert_login(p, u, pw)
    print("Login saved.")

def remove_login():
    if MASTER_KEY is None:
        print("Vault is locked.")
        return

    search = input("Search for platform to remove: ").strip().lower()
    if not search:
        print("No search term provided.")
        return

    con = get_connection()
    cur = con.cursor()
    f = Fernet(MASTER_KEY)
    rows = cur.execute("SELECT platform, username, password FROM login").fetchall()
    con.close()

    found = []
    for row in rows:
        try:
            name = f.decrypt(row[0]).decode()
            user = f.decrypt(row[1]).decode()
            if SequenceMatcher(None, name.lower(), search).ratio() > 0.6:
                found.append({"name": name, "user": user, "raw": row})
        except InvalidToken:
            continue

    if not found:
        print("No matching entries found.")
        return

    print("\nMatching entries:")
    for i, item in enumerate(found, 1):
        print(f"{i:2d}. [{item['name']}]  {item['user']}")

    try:
        idx = int(input("\nNumber to delete: ")) - 1
        if idx < 0 or idx >= len(found):
            raise ValueError
        target = found[idx]
        print(f"\nDeleting: [{target['name']}] – {target['user']}")
        if input("Confirm deletion? [y/N]: ").strip().lower() not in ('y', 'yes'):
            print("Cancelled.")
            return

        if delete_login(*target["raw"]):
            print("Entry removed.")
        else:
            print("Entry not found (already removed?).")
    except (ValueError, IndexError):
        print("Invalid selection.")

# ────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────
commands = {
    "help": help_menu, "h": help_menu,
    "add": add_login,
    "logs": show_logins, "logins": show_logins,
    "rm": remove_login,
    "clear": lambda: system("clear" if os.name != 'nt' else "cls"),
}

def cleanup():
    global MASTER_KEY
    MASTER_KEY = None
    gc.collect()
    sys.exit(0)

def main():
    if len(sys.argv) == 1:
        system("clear" if os.name != 'nt' else "cls")

    con = get_connection()
    initialize_database(con)
    has_master = con.execute("SELECT 1 FROM master").fetchone() is not None
    con.close()

    # One-shot mode
    if len(sys.argv) > 1:
        flag = sys.argv[1].removeprefix("--").lower()
        if flag in ("register", "reg"):
            ask_for_master_pass("register")
            cleanup()
        elif flag in commands:
            if not has_master:
                print("No master password set. Run --register first.")
                sys.exit(1)
            ask_for_master_pass("login")
            commands[flag]()
            cleanup()
        else:
            print(f"Unknown flag: {sys.argv[1]}")
            help_menu()
            cleanup()

    # Interactive mode
    if not has_master:
        print("No master password found.")
        ask_for_master_pass("register")
    else:
        ask_for_master_pass("login")

    print("\nType 'help' for commands.")

    try:
        while True:
            line = input(f"{PACNAME}> ").strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].removeprefix("--").lower()

            if cmd in commands:
                commands[cmd]()
            elif cmd in ("exit", "quit", "q"):
                break
            else:
                print(f"Unknown command '{cmd}'. Type 'help' for help.")
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        cleanup()

if __name__ == "__main__":
    main()