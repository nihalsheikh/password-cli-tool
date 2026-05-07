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

class SecureVault:
    """Handles encrypted storage of password entries."""
    def __init__(self, master_password: str):
        self.master_password = master_password

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return kdf.derive(self.master_password.encode())

    def save(self, entries: list[dict], file_path: Path = VAULT_FILE):
        if not HAS_CRYPTO:
            rprint("[bold red]Error:[/] 'cryptography' library is required for secure storage.")
            sys.exit(1)

        salt = os.urandom(KDF_SALT_SIZE)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(GCM_NONCE_SIZE)

        data = json.dumps(entries).encode()
        ciphertext = aesgcm.encrypt(nonce, data, None)

        with open(file_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

    def load(self, file_path: Path = VAULT_FILE) -> list[dict]:
        if not file_path.exists():
            return []

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
            return json.loads(decrypted_data.decode())
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

    entries = vault.load()

    if args.add:
        name = input("Entry Name (e.g. Github): ").strip()
        url = input("URL: ").strip()
        user = input("Username: ").strip()
        pwd = getpass.getpass("Password (leave blank to generate): ") or generate_password()
        entries.append({"name": name, "url": url, "username": user, "password": pwd, "note": ""})
        vault.save(entries)
        rprint(f"[bold green]Success:[/] Entry for {name} saved.")
    
    elif args.search:
        results = [e for e in entries if args.search.lower() in e['name'].lower()]
        _display_results(results)
    
    elif args.list:
        _display_results(entries)
    
    else:
        # Interactive Menu
        while True:
            rprint("\n[bold]1.[/] List  [bold]2.[/] Add  [bold]3.[/] Search  [bold]4.[/] Exit")
            choice = input("Select: ").strip()
            if choice == "1": _display_results(vault.load())
            elif choice == "2": 
                # Simplified add for menu
                name = input("Name: ")
                user = input("User: ")
                pwd = generate_password()
                entries = vault.load()
                entries.append({"name": name, "url": "", "username": user, "password": pwd, "note": ""})
                vault.save(entries)
                rprint("[green]Saved.[/]")
            elif choice == "3":
                q = input("Query: ")
                _display_results([e for e in vault.load() if q.lower() in e['name'].lower()])
            elif choice == "4": break

if __name__ == "__main__":
    main()
