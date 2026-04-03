import csv
import string
import pytest
from pathlib import Path

from project import (
    CSV_HEADER,
    _get_name_from_url,
    _is_valid_url,
    copy_to_clipboard,
    delete_password,
    export_passwords,
    find_passwords,
    generate_password,
    import_passwords,
    is_password_strong,
    store_password,
    update_password,
    view_passwords,
    search_passwords,
)


@pytest.fixture
def temp_password_file(tmp_path: Path) -> Path:
    # check with a temporary password.csv file to avoid affecting real data
    return tmp_path / "test_passwords.csv"


@pytest.fixture
def seeded_file(tmp_path: Path) -> Path:
    # Provide a CSV file with sample entries for testing view/search/delete functionality
    path = tmp_path / "seeded.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerow(
            {
                "name": "",
                "url": "https://example.com",
                "username": "user1",
                "password": "secret123",
                "note": "",
            }
        )
        writer.writerow(
            {
                "name": "",
                "url": "https://github.com",
                "username": "dev42",
                "password": "gh_token_abc",
                "note": "",
            }
        )
    return path


# --- is_password_strong ---
class TestIsPasswordStrong:
    def test_strong_password(self):
        assert is_password_strong("Str0ng!Pass")

    def test_strong_password_with_various_special(self):
        assert is_password_strong("Test@12345")
        assert is_password_strong("MyPass#1")

    def test_missing_uppercase(self):
        assert not is_password_strong("weakpass1#")

    def test_missing_lowercase(self):
        assert not is_password_strong("WEAKPASS1#")

    def test_missing_digit(self):
        assert not is_password_strong("NoDigitHere!")

    def test_missing_special(self):
        assert not is_password_strong("N0specialChar")

    def test_too_short(self):
        assert not is_password_strong("Ab1!d")

    def test_empty_string(self):
        assert not is_password_strong("")


# --- generate_password ---
class TestGeneratePassword:
    def test_default_length(self):
        password = generate_password()
        assert len(password) == 8

    def test_custom_length(self):
        for length in [10, 16, 32, 50]:
            assert len(generate_password(length=length)) == length

    def test_length_eight(self):
        assert len(generate_password(length=8)) == 8

    def test_length_below_minimum_raises(self):
        with pytest.raises(ValueError, match="at least 8"):
            generate_password(length=7)

    def test_no_charset_raises(self):
        with pytest.raises(ValueError, match="At least one character set"):
            generate_password(
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_special=False,
            )

    def test_contains_uppercase(self):
        password = generate_password(length=100)
        assert any(c in string.ascii_uppercase for c in password)

    def test_contains_lowercase(self):
        password = generate_password(length=100)
        assert any(c in string.ascii_lowercase for c in password)

    def test_contains_digit(self):
        password = generate_password(length=100)
        assert any(c in string.digits for c in password)

    def test_contains_special(self):
        password = generate_password(length=100)
        assert any(c in string.punctuation for c in password)

    def test_uppercase_only(self):
        password = generate_password(
            length=20, use_lowercase=False, use_digits=False, use_special=False
        )
        assert all(c in string.ascii_uppercase for c in password)

    def test_digits_only(self):
        password = generate_password(
            length=20, use_uppercase=False, use_lowercase=False, use_special=False
        )
        assert all(c in string.digits for c in password)

    def test_custom_special_chars(self):
        password = generate_password(
            length=30,
            use_uppercase=False,
            use_lowercase=False,
            use_digits=False,
            use_special=True,
            special_chars="@#",
        )
        assert all(c in "@#" for c in password)

    def test_randomness(self):
        p1 = generate_password(length=20)
        p2 = generate_password(length=20)
        assert p1 != p2


# --- copy_to_clipboard ---
class TestCopyToClipboard:
    def test_returns_boolean(self):
        result = copy_to_clipboard("test string")
        assert isinstance(result, bool)


# --- _get_name_from_url ---
class TestGetNameFromUrl:
    def test_https_domain(self):
        assert _get_name_from_url("https://example.com") == "example.com"

    def test_http_domain(self):
        assert _get_name_from_url("http://github.com/login") == "github.com"

    def test_subdomain(self):
        assert (
            _get_name_from_url("https://sub.example.org/path?q=1") == "sub.example.org"
        )

    def test_no_protocol(self):
        assert _get_name_from_url("example.com/path") == "example.com"

    def test_plain_domain(self):
        assert _get_name_from_url("example.com") == "example.com"

    def test_port_number(self):
        assert _get_name_from_url("http://localhost:8080/api") == "localhost:8080"


# --- store_password ---
class TestStorePassword:
    def test_store_new_password(self, temp_password_file):
        assert store_password(
            "https://example.com", "user1", "secret123", file_path=temp_password_file
        )
        entries = _read_entries(temp_password_file)
        assert len(entries) == 1
        assert entries[0]["url"] == "https://example.com"
        assert entries[0]["username"] == "user1"
        assert entries[0]["password"] == "secret123"
        assert entries[0]["name"] == "example.com"

    def test_store_allows_duplicates_same_url_username(self, temp_password_file):
        store_password("https://example.com", "user1", "pass1", temp_password_file)
        store_password("https://example.com", "user1", "pass2", temp_password_file)
        entries = _read_entries(temp_password_file)
        assert len(entries) == 2

    def test_store_note_field(self, temp_password_file):
        store_password(
            "https://example.com", "user1", "secret123",
            file_path=temp_password_file, note="my work account"
        )
        entries = _read_entries(temp_password_file)
        assert len(entries) == 1
        assert entries[0]["note"] == "my work account"

    def test_store_note_empty_default(self, temp_password_file):
        store_password(
            "https://example.com", "user1", "secret123", file_path=temp_password_file
        )
        entries = _read_entries(temp_password_file)
        assert entries[0]["note"] == ""

    def test_store_preserves_other_entries(self, seeded_file):
        store_password("https://newsite.com", "bob", "bobpass", seeded_file)
        entries = _read_entries(seeded_file)
        assert len(entries) == 3

    def test_store_different_users_same_url(self, temp_password_file):
        store_password("https://example.com", "user1", "pass1", temp_password_file)
        store_password("https://example.com", "user2", "pass2", temp_password_file)
        entries = _read_entries(temp_password_file)
        assert len(entries) == 2


# --- view_passwords ---
class TestViewPasswords:
    def test_view_returns_all(self, seeded_file):
        entries = view_passwords(seeded_file)
        assert len(entries) == 2

    def test_view_empty_file(self, temp_password_file):
        entries = view_passwords(temp_password_file)
        assert len(entries) == 0


# --- search_passwords ---
class TestSearchPasswords:
    def test_search_by_url(self, seeded_file):
        results = search_passwords("example", seeded_file)
        assert len(results) == 1
        assert results[0]["username"] == "user1"

    def test_search_by_username(self, seeded_file):
        results = search_passwords("dev42", seeded_file)
        assert len(results) == 1
        assert results[0]["url"] == "https://github.com"

    def test_search_case_insensitive(self, seeded_file):
        results = search_passwords("EXAMPLE", seeded_file)
        assert len(results) == 1

    def test_search_no_match(self, seeded_file):
        results = search_passwords("nonexistent", seeded_file)
        assert len(results) == 0

    def test_search_partial_match(self, seeded_file):
        results = search_passwords("hub", seeded_file)
        assert len(results) == 1  # "github.com" contains "hub"


# --- find_passwords ---
class TestFindPasswords:
    def test_find_by_name(self, seeded_file):
        results = find_passwords("example", seeded_file)
        assert len(results) == 1
        assert results[0][0]["username"] == "user1"

    def test_find_by_url_partial(self, seeded_file):
        results = find_passwords("hub", seeded_file)
        assert len(results) == 1  # github.com

    def test_find_by_username(self, seeded_file):
        results = find_passwords("dev42", seeded_file)
        assert len(results) == 1
        assert results[0][0]["url"] == "https://github.com"

    def test_find_no_match(self, seeded_file):
        results = find_passwords("nonexistent", seeded_file)
        assert len(results) == 0

    def test_find_returns_original_index(self, seeded_file):
        results = find_passwords("github", seeded_file)
        assert len(results) == 1
        _, idx = results[0]
        assert isinstance(idx, int)


# --- update_password ---
class TestUpdatePassword:
    def test_update_password(self, seeded_file):
        assert update_password(0, "new_secret", seeded_file)
        entries = _read_entries(seeded_file)
        assert entries[0]["password"] == "new_secret"

    def test_update_second_entry(self, seeded_file):
        assert update_password(1, "new_gh_token", seeded_file)
        entries = _read_entries(seeded_file)
        assert entries[1]["password"] == "new_gh_token"

    def test_update_invalid_index(self, seeded_file):
        assert not update_password(99, "password", seeded_file)

    def test_update_negative_index(self, seeded_file):
        assert not update_password(-1, "password", seeded_file)


# --- delete_password ---
class TestDeletePassword:
    def test_delete_by_index(self, seeded_file):
        assert delete_password(0, seeded_file)
        entries = _read_entries(seeded_file)
        assert len(entries) == 1
        assert entries[0]["username"] == "dev42"

    def test_delete_second_entry(self, seeded_file):
        assert delete_password(1, seeded_file)
        entries = _read_entries(seeded_file)
        assert len(entries) == 1
        assert entries[0]["username"] == "user1"

    def test_delete_invalid_index(self, seeded_file):
        assert not delete_password(99, seeded_file)

    def test_delete_negative_index(self, seeded_file):
        assert not delete_password(-1, seeded_file)

    def test_delete_last_entry(self, temp_password_file):
        store_password("https://only.com", "lonely", "pass", temp_password_file)
        assert delete_password(0, temp_password_file)
        entries = _read_entries(temp_password_file)
        assert len(entries) == 0


# --- export_passwords ---
class TestExportPasswords:
    def test_export_non_empty(self, seeded_file, tmp_path):
        export_path = tmp_path / "exported.csv"
        assert export_passwords(export_path, seeded_file)
        assert export_path.exists()
        entries = _read_entries(export_path)
        assert len(entries) == 2

    def test_export_empty_file(self, temp_password_file, tmp_path):
        export_path = tmp_path / "empty_export.csv"
        assert not export_passwords(export_path, temp_password_file)
        assert not export_path.exists()

    def test_export_browser_compatible(self, seeded_file, tmp_path):
        export_path = tmp_path / "browser_export.csv"
        export_passwords(export_path, seeded_file)
        with open(export_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            assert header == CSV_HEADER


# --- import_passwords ---
class TestImportPasswords:
    def test_import_new_passwords(self, temp_password_file, tmp_path):
        source = tmp_path / "import_source.csv"
        with open(source, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
            writer.writeheader()
            writer.writerow(
                {
                    "name": "",
                    "url": "https://newsite.com",
                    "username": "imported_user",
                    "password": "imported_pass",
                    "note": "",
                }
            )

        count = import_passwords(source, temp_password_file)
        assert count == 1
        entries = _read_entries(temp_password_file)
        assert len(entries) == 1
        assert entries[0]["username"] == "imported_user"

    def test_import_updates_existing(self, seeded_file, tmp_path):
        source = tmp_path / "update_import.csv"
        with open(source, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
            writer.writeheader()
            writer.writerow(
                {
                    "name": "",
                    "url": "https://example.com",
                    "username": "user1",
                    "password": "updated_from_import",
                    "note": "",
                }
            )

        count = import_passwords(source, seeded_file)
        # 0 new because the entry already exists
        assert count == 0
        entries = _read_entries(seeded_file)
        assert entries[0]["password"] == "updated_from_import"

    def test_import_mixed_new_and_existing(self, seeded_file, tmp_path):
        source = tmp_path / "mixed_import.csv"
        with open(source, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
            writer.writeheader()
            writer.writerow(
                {
                    "url": "https://example.com",
                    "username": "user1",
                    "password": "updated",
                    "note": "",
                }
            )
            writer.writerow(
                {
                    "name": "",
                    "url": "https://brandnew.com",
                    "username": "fresh",
                    "password": "fresh_pass",
                    "note": "",
                }
            )

        count = import_passwords(source, seeded_file)
        assert count == 1  # 1 new entry
        entries = _read_entries(seeded_file)
        assert len(entries) == 3  # 2 original + 1 new

    def test_import_file_not_found(self, temp_password_file):
        assert import_passwords("nonexistent_file.csv", temp_password_file) == 0

    def test_import_empty_file(self, temp_password_file, tmp_path):
        source = tmp_path / "empty.csv"
        with open(source, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)

        assert import_passwords(source, temp_password_file) == 0

    def test_import_missing_columns(self, temp_password_file, tmp_path):
        source = tmp_path / "bad_columns.csv"
        with open(source, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["website", "email", "pass"])
            writer.writerow(["https://x.com", "a@b.com", "pwd"])

        assert import_passwords(source, temp_password_file) == 0


# --- Round-trip: export then import ---
class TestRoundTrip:
    def test_export_then_import_same_data(self, seeded_file, tmp_path):
        export_path = tmp_path / "roundtrip.csv"
        dest_path = tmp_path / "roundtrip_dest.csv"

        assert export_passwords(export_path, seeded_file)
        count = import_passwords(export_path, dest_path)
        assert count == 2

        original = _read_entries(seeded_file)
        imported = _read_entries(dest_path)
        assert len(imported) == len(original)

        for orig in original:
            matching = [
                i
                for i in imported
                if i["url"] == orig["url"] and i["username"] == orig["username"]
            ]
            assert len(matching) == 1
            assert matching[0]["password"] == orig["password"]


def _read_entries(file_path: Path) -> list[dict]:
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


# --- _is_valid_url ---
class TestIsValidUrl:
    def test_https_with_domain(self):
        assert _is_valid_url("https://example.com")

    def test_https_with_www(self):
        assert _is_valid_url("https://www.example.com")

    def test_http_with_domain(self):
        assert _is_valid_url("http://example.com")

    def test_http_with_path(self):
        assert _is_valid_url("https://example.com/login")

    def test_subdomain(self):
        assert _is_valid_url("https://sub.example.com")

    def test_no_protocol(self):
        assert not _is_valid_url("example.com")

    def test_plain_text(self):
        assert not _is_valid_url("hello world")

    def test_empty(self):
        assert not _is_valid_url("")
