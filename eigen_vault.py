import argparse
import csv
import getpass
import json
import os
import re
import secrets
import string
import sys
from pathlib import Path

import pyperclip

# Third-party imports for security and UI
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Initialize Rich Console
console = Console()

# Constants
VAULT_FILE = Path.home() / ".eigenvault.ev"
CSV_HEADER = ["name", "url", "username", "password", "note"]
KDF_ITERATIONS = 600000
KDF_SALT_SIZE = 16
GCM_NONCE_SIZE = 12

import hmac
import hashlib
import time
import base64
import struct

...

def get_totp_code(secret):
    """Minimal TOTP implementation (HMAC-SHA1)"""
    # Base32 decode
    secret = secret.upper()
    missing_padding = len(secret) % 8
    if missing_padding:
        secret += '=' * (8 - missing_padding)
    key = base64.b32decode(secret)
    
    # Time step
    intervals = int(time.time() // 30)
    msg = struct.pack(">Q", intervals)
    
    # HMAC-SHA1
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    
    # Dynamic Truncation
    offset = hmac_hash[-1] & 0x0f
    code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7fffffff
    
    return str(code % 1000000).zfill(6)

...

class SecureVault:
    """Handles encrypted storage of password entries."""
    def __init__(self, master_password: str):
        self.master_password = master_password

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=150000, # Aligned with extension
        )
        return kdf.derive(self.master_password.encode())

    def save(self, entries: list[dict], mfa_settings: dict = None, file_path: Path = VAULT_FILE):
        if not HAS_CRYPTO:
            rprint("[bold red]Error:[/] 'cryptography' library is required for secure storage.")
            sys.exit(1)

        salt = os.urandom(KDF_SALT_SIZE)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(GCM_NONCE_SIZE)

        vault_data = {
            "entries": entries,
            "mfa": mfa_settings or {"totpEnabled": False, "otpEnabled": False}
        }
        
        data = json.dumps(vault_data).encode()
        ciphertext = aesgcm.encrypt(nonce, data, None)

        with open(file_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

    def load(self, file_path: Path = VAULT_FILE) -> tuple[list[dict], dict]:
        if not file_path.exists():
            return [], {"totpEnabled": False, "otpEnabled": False}

        if not HAS_CRYPTO:
            rprint("[bold red]Error:[/] 'cryptography' library is required for secure storage.")
            sys.exit(1)

        with open(file_path, "rb") as f:
            data = f.read()
            salt = data[:KDF_SALT_SIZE]
            nonce = data[KDF_SALT_SIZE:KDF_SALT_SIZE+GCM_NONCE_SIZE]
            ciphertext = data[KDF_SALT_SIZE+GCM_NONCE_SIZE:]

        try:
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            parsed = json.loads(decrypted_data.decode())
            
            # Handle legacy format
            if isinstance(parsed, list):
                return parsed, {"totpEnabled": False, "otpEnabled": False}
            
            return parsed.get("entries", []), parsed.get("mfa", {"totpEnabled": False, "otpEnabled": False})
        except Exception:
            rprint("[bold red]Error:[/] Access denied. Incorrect master password.")
            sys.exit(1)

def generate_password(length=16):
    pool = string.ascii_letters + string.digits + string.punctuation
    pwd = "".join(secrets.choice(pool) for _ in range(length))
    return pwd

def _display_header():
    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]E I G E N   V A U L T[/]\n[italic white]Securing your digital life, bit by bit.[/]",
            border_style="blue"
        ))
    else:
        print("\n=== EIGEN VAULT ===")

def _display_results(results):
    if not results:
        rprint("[yellow]No entries found.[/]")
        return
    
    if HAS_RICH:
        table = Table(title="Vault Entries", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="dim", width=15)
        table.add_column("Username", style="cyan")
        table.add_column("Password", style="green")
        table.add_column("URL", style="blue")
        
        for e in results:
            table.add_row(e['name'], e['username'], "*" * 12, e['url'])
        console.print(table)
    else:
        print(f"\n{'Name':<15} {'Username':<20} {'URL'}")
        print("-" * 50)
        for e in results:
            print(f"{e['name']:<15} {e['username']:<20} {e['url']}")

def main():
    parser = argparse.ArgumentParser(description="EigenVault: Professional Password Manager")
    parser.add_argument("-g", "--generate", action="store_true", help="Generate a secure password")
    parser.add_argument("-l", "--length", type=int, default=16, help="Password length")
    parser.add_argument("-a", "--add", action="store_true", help="Add a new entry")
    parser.add_argument("-s", "--search", help="Search the vault")
    parser.add_argument("-ls", "--list", action="store_true", help="List all entries")
    parser.add_argument("-e", "--export", metavar="FILE", help="Export to CSV")
    parser.add_argument("-i", "--import-csv", metavar="FILE", help="Import from CSV")
    
    args = parser.parse_args()

    if args.generate:
        pwd = generate_password(args.length)
        rprint(f"[bold green]Generated:[/] {pwd}")
        pyperclip.copy(pwd)
        rprint("[dim]Copied to clipboard.[/]")
        return

    _display_header()

    if not HAS_CRYPTO or not HAS_RICH:
        rprint("[yellow]Warning:[/] Some UI or security components are missing. Run [bold]pip install cryptography rich[/]")

    # Master Password Handling
    if not VAULT_FILE.exists():
        rprint("[bold cyan]Welcome to EigenVault![/] Let's set up your secure storage.")
        while True:
            p1 = getpass.getpass("Set Master Password: ")
            p2 = getpass.getpass("Confirm Master Password: ")
            if p1 == p2 and len(p1) >= 8:
                master_pwd = p1
                break
            rprint("[red]Passwords must match and be at least 8 characters.[/]")
        vault = SecureVault(master_pwd)
        vault.save([])
    else:
        master_pwd = getpass.getpass("Master Password: ")
        vault = SecureVault(master_pwd)

    entries, mfa_settings = vault.load()

    # MFA Challenge
    if mfa_settings.get("totpEnabled"):
        code = input("MFA Code: ").strip()
        expected = get_totp_code(mfa_settings["totpSecret"])
        if code != expected:
            rprint("[bold red]Error:[/] Invalid MFA code.")
            sys.exit(1)

    if args.add:
...
    elif args.list:
        _display_results(entries)
    
    else:
        # Interactive Menu
        while True:
            rprint("\n[bold]1.[/] List  [bold]2.[/] Add  [bold]3.[/] Search  [bold]4.[/] Settings  [bold]5.[/] Exit")
            choice = input("Select: ").strip()
            if choice == "1": 
                entries, _ = vault.load()
                _display_results(entries)
            elif choice == "2": 
                name = input("Name: ")
                user = input("User: ")
                pwd = input("Password (blank to gen): ") or generate_password()
                entries, mfa = vault.load()
                entries.append({"name": name, "url": "", "username": user, "password": pwd, "note": ""})
                vault.save(entries, mfa)
                rprint("[green]Saved.[/]")
            elif choice == "3":
                q = input("Query: ")
                entries, _ = vault.load()
                _display_results([e for e in entries if q.lower() in e['name'].lower()])
            elif choice == "4":
                # Settings Menu
                rprint("\n[bold]Settings:[/]")
                rprint("1. Setup TOTP MFA")
                rprint("2. Disable MFA")
                rprint("3. Generate Recovery Key")
                s_choice = input("Select: ").strip()
                
                if s_choice == "1":
                    # Simple Base32 secret generation
                    secret = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
                    rprint(f"\n[cyan]Add this secret to your Authenticator app:[/] [bold]{secret}[/]")
                    code = input("Verify code: ").strip()
                    if code == get_totp_code(secret):
                        mfa_settings["totpEnabled"] = True
                        mfa_settings["totpSecret"] = secret
                        vault.save(entries, mfa_settings)
                        rprint("[green]TOTP MFA Enabled.[/]")
                    else:
                        rprint("[red]Verification failed.[/]")
                
                elif s_choice == "2":
                    mfa_settings["totpEnabled"] = False
                    mfa_settings["otpEnabled"] = False
                    vault.save(entries, mfa_settings)
                    rprint("[yellow]MFA Disabled.[/]")

            elif choice == "5": break

if __name__ == "__main__":
    main()
