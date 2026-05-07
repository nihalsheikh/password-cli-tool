import os
import string
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from project import (
    is_password_strong,
    generate_password,
    _get_name_from_url,
    _is_valid_url,
    SecureVault,
    HAS_CRYPTO
)

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


# --- generate_password ---
class TestGeneratePassword:
    def test_default_length(self):
        password = generate_password()
        assert len(password) == 16

    def test_custom_length(self):
        assert len(generate_password(length=10)) == 10
        assert len(generate_password(length=32)) == 32

    def test_length_below_minimum_raises(self):
        with pytest.raises(ValueError, match="at least 8"):
            generate_password(length=7)

    def test_contains_required_sets(self):
        password = generate_password(length=100)
        assert any(c in string.ascii_uppercase for c in password)
        assert any(c in string.ascii_lowercase for c in password)
        assert any(c in string.digits for c in password)
        assert any(c in string.punctuation for c in password)


# --- _get_name_from_url ---
class TestGetNameFromUrl:
    def test_https_domain(self):
        assert _get_name_from_url("https://example.com") == "example.com"

    def test_http_domain(self):
        assert _get_name_from_url("http://github.com/login") == "github.com"

    def test_subdomain(self):
        assert _get_name_from_url("https://sub.example.org/path") == "sub.example.org"


# --- _is_valid_url ---
class TestIsValidUrl:
    def test_valid_urls(self):
        assert _is_valid_url("https://example.com")
        assert _is_valid_url("http://www.google.com/search")

    def test_invalid_urls(self):
        assert not _is_valid_url("example.com")
        assert not _is_valid_url("ftp://server.com")
        assert not _is_valid_url("just text")


# --- SecureVault (only if cryptography is available) ---
@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography library not installed")
class TestSecureVault:
    def test_vault_save_and_load(self, tmp_path):
        vault_path = tmp_path / "test.ev"
        master_pwd = "master-secret-password"
        vault = SecureVault(master_pwd)
        
        entries = [
            {"name": "test", "url": "http://test.com", "username": "user", "password": "pwd", "note": "note"}
        ]
        
        vault.save(entries, file_path=vault_path)
        assert vault_path.exists()
        
        # Load with same password
        loaded_entries = vault.load(file_path=vault_path)
        assert loaded_entries == entries

    def test_vault_wrong_password(self, tmp_path):
        vault_path = tmp_path / "test_wrong.ev"
        vault = SecureVault("password123")
        vault.save([{"data": "secret"}], file_path=vault_path)
        
        wrong_vault = SecureVault("wrong-password")
        with pytest.raises(SystemExit):
            wrong_vault.load(file_path=vault_path)
