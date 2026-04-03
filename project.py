import csv
import re
import secrets
import string
import pyperclip
from pathlib import Path

PASSWORDS_FILE = Path("passwords.csv")

# Browser compatible .csv file format
CSV_HEADER = ["name", "url", "username", "password", "note"]

# Regex for strong password validation
STRONG_PASSWORD_RE = re.compile(
    r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^a-zA-Z0-9]).{8,}$"
)


def is_password_strong(password: str) -> bool:
    # strong password validation
    return bool(STRONG_PASSWORD_RE.match(password))


def copy_to_clipboard(text: str) -> bool:
    # Copy generated password to the clipboard
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def _ensure_csv_file(file_path: Path | None = None) -> Path:
    # Create a new .csv file if it doesn't exist
    target = file_path or PASSWORDS_FILE
    if not target.exists():
        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
    return target


def _read_passwords(file_path: Path | None = None) -> list[dict]:
    # Read passwords from the .csv file
    target = _ensure_csv_file(file_path)
    try:
        with open(target, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)
    except (csv.Error, UnicodeDecodeError) as e:
        print(f"Error reading {target}: {e}")
        return []


def _write_passwords(entries: list[dict], file_path: Path | None = None) -> bool:
    # Write password entries to the .csv file
    target = _ensure_csv_file(file_path)
    try:
        with open(target, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
            writer.writeheader()
            writer.writerows(entries)
        return True
    except (csv.Error, IOError) as e:
        print(f"Error writing to {target}: {e}")
        return False


def generate_password(
    length: int = 8,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    special_chars: str = string.punctuation,
) -> str:
    if length < 8:
        raise ValueError("For a strong password, length must be at least 8.")

    pool = ""
    required = []

    if use_uppercase:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_lowercase:
        pool += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if use_special:
        pool += special_chars
        required.append(secrets.choice(special_chars))

    if not pool:
        raise ValueError("At least one character set must be selected.")

    # Default: 4 char-sets -> 4 required chars
    if length <= len(required):
        return "".join(required[:length])

    password_chars = required + [
        secrets.choice(pool) for _ in range(length - len(required))
    ]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def _is_valid_url(url: str) -> bool:
    return bool(re.match(r"^https?://(www\.)?[^/]+\.[a-zA-Z]{2,}(/.*)?", url))


def _get_name_from_url(url: str) -> str:
    # Extract website name from a URL for the name field.
    cleaned = url
    # Strip protocol
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    # Strip path, query, and fragment
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    return cleaned.rstrip("/")


def store_password(
    url: str,
    username: str,
    password: str,
    file_path: Path | None = None,
    name: str | None = None,
    note: str = "",
) -> bool:
    entries = _read_passwords(file_path)

    domain_name = name if name else _get_name_from_url(url)
    entries.append(
        {
            "name": domain_name,
            "url": url,
            "username": username,
            "password": password,
            "note": note,
        }
    )
    result = _write_passwords(entries, file_path)
    if result:
        print(f"Saved password for {username} at {url}")
    return result


def export_passwords(export_path: str | Path, file_path: Path | None = None) -> bool:
    entries = _read_passwords(file_path)
    if not entries:
        print("No saved passwords to export.")
        return False

    target = _ensure_csv_file(file_path)
    try:
        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
            writer.writeheader()
            writer.writerows(entries)
        print(f"Exported {len(entries)} password(s) to {export_path}")
        return True
    except IOError as e:
        print(f"Error exporting to {export_path}: {e}")
        return False


def import_passwords(import_path: str | Path, file_path: Path | None = None) -> int:
    import_path = Path(import_path)
    if not import_path.exists():
        print(f"File not found: {import_path}")
        return 0

    try:
        with open(import_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            imported = list(reader)
    except (csv.Error, UnicodeDecodeError, KeyError) as e:
        print(f"Error reading {import_path}: {e}")
        return 0

    if not imported:
        print("No passwords found in the import file.")
        return 0

    # Validate required columns
    required_cols = {"url", "username", "password"}
    if not required_cols.issubset(set(imported[0].keys())):
        print("Import file missing required columns (url, username, password).")
        return 0

    existing = _read_passwords(file_path)
    existing_map = {f"{e['url']}||{e['username']}": e for e in existing}

    imported_count = 0
    for entry in imported:
        key = f"{entry['url']}||{entry['username']}"
        if key in existing_map:
            existing_map[key]["password"] = entry["password"]
        else:
            row = {
                "name": "",
                "url": entry["url"],
                "username": entry["username"],
                "password": entry["password"],
                "note": "",
            }
            for col in ["name", "note"]:
                row[col] = entry.get(col, "")
            existing_map[key] = row
            imported_count += 1

    _write_passwords(list(existing_map.values()), file_path)
    print(
        f"Imported {imported_count} new password(s), updated {len(imported) - imported_count} existing."
    )
    return imported_count


def view_passwords(file_path: Path | None = None) -> list[dict]:
    entries = _read_passwords(file_path)
    if not entries:
        print("No passwords stored.")
        return entries

    print(f"\n{'URL':<35} {'Username':<25} {'Password'}")
    print("-" * 90)
    for entry in entries:
        masked = (
            entry["password"][:2] + "*" * (len(entry["password"]) - 2)
            if len(entry["password"]) > 2
            else "***"
        )
        print(f"{entry['url']:<35} {entry['username']:<25} {masked}")
    print(f"\nTotal: {len(entries)} password(s)")
    return entries


def search_passwords(query: str, file_path: Path | None = None) -> list[dict]:
    entries = _read_passwords(file_path)
    query_lower = query.lower()
    results = [
        e
        for e in entries
        if query_lower in e["url"].lower() or query_lower in e["username"].lower()
    ]

    if not results:
        print(f"No passwords found matching '{query}'.")
        return results

    print(f"\nResults for '{query}':")
    print(f"{'URL':<35} {'Username':<25} {'Password'}")
    print("-" * 90)
    for entry in results:
        masked = (
            entry["password"][:2] + "*" * (len(entry["password"]) - 2)
            if len(entry["password"]) > 2
            else "***"
        )
        print(f"{entry['url']:<35} {entry['username']:<25} {masked}")
    print(f"\nFound: {len(results)} password(s)")
    return results


def delete_password(index: int, file_path: Path | None = None) -> bool:
    # Delete a password entry by its index in the matching results.
    entries = _read_passwords(file_path)
    if index < 0 or index >= len(entries):
        print("Invalid selection.")
        return False

    removed = entries.pop(index)
    _write_passwords(entries, file_path)
    print(f"Deleted password for {removed['username']} at {removed['url']}")
    return True


def update_password(index: int, new_password: str, file_path: Path | None = None) -> bool:
    # Update the password of an entry by its index in the matching results.
    entries = _read_passwords(file_path)
    if index < 0 or index >= len(entries):
        print("Invalid selection.")
        return False

    entries[index]["password"] = new_password
    _write_passwords(entries, file_path)
    print(f"Updated password for {entries[index]['username']} at {entries[index]['url']}")
    return True


def find_passwords(query: str, file_path: Path | None = None) -> list[dict]:
    # Find all entries matching a query (name, url, or username).
    entries = _read_passwords(file_path)
    query_lower = query.lower()
    results = []
    for i, entry in enumerate(entries):
        if (
            query_lower in entry["name"].lower()
            or query_lower in entry["url"].lower()
            or query_lower in entry["username"].lower()
        ):
            results.append((entry, i))  # keep original index
    return results


def _print_menu() -> None:
    # Main menu / Dashboard
    print("\n" + "=" * 50)
    print("      Password Generator & Manager")
    print("=" * 50)
    print("1. Generate Password")
    print("2. Store Password")
    print("3. View All Passwords")
    print("4. Search Passwords")
    print("5. Update Password")
    print("6. Delete Password")
    print("7. Export Passwords (CSV)")
    print("8. Import Passwords (CSV)")
    print("9. Exit (9/q/Q)")
    print("=" * 50)


def main() -> None:
    _ensure_csv_file()

    while True:
        _print_menu()
        choice = input("\nSelect an option [1-9]: ").strip()

        match choice:
            case "1":
                _generate_password_interactive()
            case "2":
                _store_password_interactive()
            case "3":
                view_passwords()
            case "4":
                _search_passwords_interactive()
            case "5":
                _update_password_interactive()
            case "6":
                _delete_password_interactive()
            case "7":
                _export_passwords_interactive()
            case "8":
                _import_passwords_interactive()
            case "9" | "q" | "Q":
                print("Goodbye!")
                break
            case _:
                print("Invalid option. Please select 1-9.")

        input("\nPress Enter to continue...")


def _generate_password_interactive() -> None:
    while True:
        raw = input("Password length [8]: ").strip()
        try:
            length = int(raw) if raw else 8
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        if length < 8:
            print("Password length must be at least 8. Try again.")
            continue
        break

    digits = (
        input("Include digits & special characters? [y/n] (default y): ")
        .strip()
        .lower()
    )
    use_chars = digits not in ("n", "no")

    opts = {}
    if use_chars:
        opts = {"use_digits": True, "use_special": True}
    else:
        opts = {"use_digits": False, "use_special": False}

    while True:
        password = generate_password(length, **opts)

        strong = is_password_strong(password)
        print(f"\nGenerated password: {password}")
        if strong:
            print("Strength: Strong")
        else:
            print("Strength: Weak")

        if copy_to_clipboard(password):
            print("Password copied to clipboard!")
        else:
            print("Could not copy to clipboard. Install pyperclip (pip install pyperclip).")

        while True:
            choice = input("Accept this password? [y/n/r=regenerate]: ").strip().lower()
            if choice in ("y", "yes", "n", "no", "r"):
                break
            print("Enter y, n, or r.")

        if choice == "y":
            break
        # "n" or "r": regenerate

    while True:
        url = input("Website URL: ").strip()
        if not url:
            print("URL is required. Try again.")
            continue
        if _is_valid_url(url):
            break
        print("Invalid URL format. Please use https://example.com or http://www.example.com")

    save = input("Save this password? [y/n]: ").strip().lower()
    if save in ("y", "yes"):
        username = input("Username: ").strip()
        if username:
            note = input("Note [optional]: ").strip()
            store_password(url, username, password, note=note)


def _store_password_interactive() -> None:
    while True:
        url = input("Website URL: ").strip()
        if not url:
            print("URL is required. Try again.")
            continue
        if _is_valid_url(url):
            break
        print("Invalid URL format. Please use https://example.com or http://www.example.com")
    while True:
        username = input("Username: ").strip()
        if username:
            break
        print("Username is required. Try again.")

    use_generated = input("Generate a password? [y/n] (default y): ").strip().lower()
    if use_generated in ("y", "yes", ""):
        password = generate_password()
        print(f"Generated password: {password}")
    else:
        while True:
            password = input("Enter password: ").strip()
            if password:
                break
            print("Password cannot be empty. Try again.")

    note = input("Note [optional]: ").strip()
    store_password(url, username, password, note=note)


def _search_passwords_interactive() -> None:
    while True:
        query = input("Search by URL or username: ").strip()
        if query:
            break
        print("Search query cannot be empty. Try again.")
    search_passwords(query)


def _update_password_interactive() -> None:
    while True:
        query = input("Enter website name, URL, or username to search: ").strip()
        if query:
            break
        print("Search query cannot be empty. Try again.")

    results = find_passwords(query)
    if not results:
        print("No matching passwords found.")
        return

    print()
    for num, (entry, _idx) in enumerate(results, start=1):
        masked = (
            entry["password"][:2] + "*" * (len(entry["password"]) - 2)
            if len(entry["password"]) > 2
            else "***"
        )
        print(
            f"  {num}. {entry['url']:<35} "
            f"{entry['username']:<25} {masked}"
        )

    while True:
        raw = input(
            f"Select entry to update [1-{len(results)}]: "
        ).strip()
        try:
            choice = int(raw)
            if 1 <= choice <= len(results):
                break
            print(f"Please enter a number between 1 and {len(results)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    _, original_index = results[choice - 1]
    entry = results[choice - 1][0]

    use_generated = input("Generate a new password? [y/n] (default y): ").strip().lower()
    if use_generated in ("y", "yes", ""):
        new_password = generate_password()
        print(f"Generated password: {new_password}")
    else:
        while True:
            new_password = input("Enter new password: ").strip()
            if new_password:
                break
            print("Password cannot be empty. Try again.")

    update_password(original_index, new_password)


def _delete_password_interactive() -> None:
    while True:
        query = input("Enter website name, URL, or username to search: ").strip()
        if query:
            break
        print("Search query cannot be empty. Try again.")

    results = find_passwords(query)
    if not results:
        print("No matching passwords found.")
        return

    print()
    for num, (entry, _idx) in enumerate(results, start=1):
        masked = (
            entry["password"][:2] + "*" * (len(entry["password"]) - 2)
            if len(entry["password"]) > 2
            else "***"
        )
        print(
            f"  {num}. {entry['url']:<35} "
            f"{entry['username']:<25} {masked}"
        )

    while True:
        raw = input(
            f"Select entry to delete [1-{len(results)}]: "
        ).strip()
        try:
            choice = int(raw)
            if 1 <= choice <= len(results):
                break
            print(f"Please enter a number between 1 and {len(results)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    _, original_index = results[choice - 1]
    confirm = input("Are you sure? [y/n]: ").strip().lower()
    if confirm not in ("y", "yes"):
        print("Deletion cancelled.")
        return

    delete_password(original_index)


def _export_passwords_interactive() -> None:
    default_name = "exported_passwords.csv"
    while True:
        filepath = input(f"Export file path [{default_name}]: ").strip() or default_name
        if Path(filepath).exists():
            confirm = (
                input(f"'{filepath}' already exists. Overwrite? [y/n]: ")
                .strip()
                .lower()
            )
            if confirm not in ("y", "yes"):
                print("Export cancelled.")
                return
        break
    export_passwords(filepath)


def _import_passwords_interactive() -> None:
    while True:
        filepath = input("Path to CSV file: ").strip()
        if not filepath:
            print("File path cannot be empty. Try again.")
            continue
        if not Path(filepath).exists():
            print(f"File not found: {filepath}. Try again.")
            continue
        break
    import_passwords(filepath)


if __name__ == "__main__":
    main()
