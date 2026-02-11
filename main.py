import sqlite3
import base64
import os
import hashlib
import sys
import gc
from os import system
from difflib import SequenceMatcher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'PasswordManager.db')
PACNAME = "pwm"
MASTERPASSWORD = None
con = sqlite3.connect(DB_PATH)
cur = con.cursor()

def get_masked_input(prompt=""):
    print(prompt, end="", flush=True)
    password = ""
    while True:
        # Check if running on Windows
        if os.name == 'nt':
            import msvcrt
            char = msvcrt.getch().decode('utf-8')
        else:
            # Linux/Mac logic
            import tty, termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                char = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        if char == '\r' or char == '\n':  # Enter key
            print()
            break
        elif char == '\x08' or char == '\x7f':  # Backspace
            if len(password) > 0:
                password = password[:-1]
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        else:
            password += char
            sys.stdout.write('*')
            sys.stdout.flush()
    return password

# --- CORE CRYPTO ---
def get_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    raw_key = kdf.derive(password.encode('utf-8'))
    fernet_key = base64.urlsafe_b64encode(raw_key)
    
    # Memory management: Clean up raw bytes
    del raw_key
    return fernet_key

# --- DATABASE LOGIC ---
def initialize_database() -> None:
    cur.execute("CREATE TABLE IF NOT EXISTS login(platform BLOB, username BLOB, password BLOB)")
    cur.execute("CREATE TABLE IF NOT EXISTS master(masterpassword BLOB, salt BLOB)")
    con.commit()

    row = cur.execute("SELECT masterpassword FROM master").fetchone()
    if not row:
        print("No master password found.")
        ask_for_master_pass("register")
    else:
        ask_for_master_pass("login")

def ask_for_master_pass(mode="login"):
    global MASTERPASSWORD
    while True:
        if mode == "register":
            mpass = get_masked_input("Pick a master password (min 8 chars): ")
            if len(mpass) < 7: 
                print("Too short!")
                continue
            conf = input("Are you sure? This will be your encryption key. Y/n: ")
            if conf.lower() == 'y' or conf == '':
                new_salt = os.urandom(16)
                # This is our actual encryption key
                MASTERPASSWORD = get_key(mpass, new_salt) 
                
                # We store a HASH of the key for verification, NOT the key itself
                verification_hash = hashlib.sha256(MASTERPASSWORD).digest()
                
                cur.execute("INSERT INTO master VALUES (?, ?)", (verification_hash, new_salt))
                con.commit()
                mpass = None
                break
        else:
            mpass = get_masked_input("Enter master password: ")
            row = cur.execute("SELECT masterpassword, salt FROM master").fetchone()
            if row:
                stored_verification, stored_salt = row
                # Derive the key from what the user just typed
                attempt_key = get_key(mpass, stored_salt)
                # Hash the attempt to see if it matches the stored verification
                if hashlib.sha256(attempt_key).digest() == stored_verification:
                    MASTERPASSWORD = attempt_key
                    print("Access Granted!")
                    mpass = None
                    gc.collect() 
                    break
            print("Incorrect password.")

# --- CRUD OPERATIONS ---
def insert_login(platform, username, password) -> None:
    f = Fernet(MASTERPASSWORD)
    cur.execute("INSERT INTO login VALUES (?, ?, ?)", (
        f.encrypt(platform.encode()), 
        f.encrypt(username.encode()), 
        f.encrypt(password.encode())
    ))
    con.commit()
    gc.collect() # Clean up encryption remnants

def delete_login(p_enc, u_enc, pw_enc):
    cur.execute("DELETE FROM login WHERE platform = ? AND username = ? AND password = ?", 
                (p_enc, u_enc, pw_enc))
    con.commit()

# --- COMMAND FUNCTIONS ---
def help_menu():
    print(f"\n--- {PACNAME.upper()} HELP ---")
    print("--add  : Add a login")
    print("--logs : Show all logins")
    print("--rm   : Remove a login")
    print("--exit : Quit")

def show_logins():
    f = Fernet(MASTERPASSWORD)
    logs = cur.execute("SELECT platform, username, password FROM login").fetchall()
    if not logs: print("No logins saved."); return
    
    print(f"\n--- {PACNAME.upper()} LOGINS ---")
    for log in logs:
        p = f.decrypt(log[0]).decode()
        u = f.decrypt(log[1]).decode()
        pw = f.decrypt(log[2]).decode()
        print(f"[{p}] User: {u} | Pass: {pw}")
        # Help garbage collector
        p = u = pw = None 
    gc.collect()

def add_login():
    p = input("Platform: ")
    u = input("Username: ")
    pw = input("Password: ")
    
    print(f"\nConfirm Login Data:")
    print(f"Platform: {p}")
    print(f"Username: {u}")
    print(f"Password: {'*' * len(pw)}")
    
    confirm = input("Save this login? Y/n: ")
    if confirm.lower() == 'y' or confirm == '':
        insert_login(p, u, pw)
        print("Successfully saved!")
    else:
        print("Action cancelled.")
    p = u = pw = None # Memory wipe

def remove_login():
    f = Fernet(MASTERPASSWORD)
    search = input("Enter platform name to search for deletion: ").lower()
    logs = cur.execute("SELECT platform, username, password FROM login").fetchall()
    
    found = []
    for row in logs:
        p_name = f.decrypt(row[0]).decode()
        u_name = f.decrypt(row[1]).decode()
        if SequenceMatcher(None, p_name.lower(), search).ratio() > 0.6:
            found.append({"name": p_name, "user": u_name, "raw": row})

    if not found: 
        print("No matching platforms found.")
        return

    print("\n--- Search Results ---")
    for i, item in enumerate(found, 1):
        print(f"{i}. [{item['name']}] | User: {item['user']}")
    
    try:
        choice = int(input("\nPick the number to delete: ")) - 1
        if choice < 0 or choice >= len(found): raise IndexError
        
        target = found[choice]
        print(f"\nWARNING: You are about to delete the login for [{target['name']}].")
        confirm = input("Are you absolutely sure? Y/n: ")
        
        if confirm.lower() == 'y' or confirm == '':
            raw_data = target["raw"]
            delete_login(raw_data[0], raw_data[1], raw_data[2])
            print("Successfully removed!")
        else:
            print("Deletion cancelled.")
    except (ValueError, IndexError):
        print("Invalid selection. Action interrupted.")

# --- MAIN LOOP ---
commands = {
    "help": help_menu, "h": help_menu,
    "add": add_login,
    "logs": show_logins, "logins": show_logins,
    "rm": remove_login
}

def main():
    # Only clear screen if not being used as a one-off CLI tool
    if len(sys.argv) == 1:
        system("clear")
    
    initialize_database()

    # --- CLI ARGUMENT HANDLING ---
    # This allows: python main.py --logs
    if len(sys.argv) > 1:
        flag = sys.argv[1].removeprefix("--")
        if flag in commands:
            commands[flag]()
            cleanup_and_exit()
        elif flag == "exit":
            cleanup_and_exit()
        else:
            print(f"Unknown flag: --{flag}")
            help_menu()
            cleanup_and_exit()

    # --- INTERACTIVE LOOP ---
    try:
        while True:
            raw_in = input(f"\n> ").strip()
            if not raw_in: continue
            
            parts = raw_in.split()
            
            # Allow just typing "--logs" or "pwm --logs"
            if parts[0] == PACNAME:
                if len(parts) < 2:
                    help_menu()
                    continue
                cmd = parts[1].removeprefix("--")
            else:
                cmd = parts[0].removeprefix("--")

            if cmd in commands:
                commands[cmd]()
            elif cmd == "exit" or cmd == "quit":
                break
            else:
                print(f"Unknown command. Try '{PACNAME} --help'")
    except KeyboardInterrupt:
        print("\nGoodbye!")
    finally:
        cleanup_and_exit()

def cleanup_and_exit():
    global MASTERPASSWORD
    MASTERPASSWORD = None
    con.close()
    sys.exit()

if __name__ == "__main__":
    main()