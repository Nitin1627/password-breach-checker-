"""
Unit tests for utility functions.
"""

import pytest
import hashlib
from app.utils import (
    hash_password_sha1,
    get_k_anonymity_parts,
    mask_password,
    format_breach_count,
    truncate_string,
    ValidationError,
)


class TestHashPasswordSHA1:
    """Tests for SHA1 password hashing."""

    def test_hash_password_sha1_basic(self):
        """Test basic password hashing."""
        password = "password"
        expected = hashlib.sha1(password.encode()).hexdigest().upper()
        result = hash_password_sha1(password)
        assert result == expected

    def test_hash_password_sha1_empty_raises_error(self):
        """Test that empty password raises ValidationError."""
        with pytest.raises(ValidationError, match="empty"):
            hash_password_sha1("")

    def test_hash_password_sha1_unicode(self):
        """Test hashing with unicode characters."""
        password = "héllo wörld 🎉"
        expected = hashlib.sha1(password.encode()).hexdigest().upper()
        result = hash_password_sha1(password)
        assert result == expected

    def test_hash_password_sha1_long_password(self):
        """Test hashing long password."""
        password = "a" * 1000
        expected = hashlib.sha1(password.encode()).hexdigest().upper()
        result = hash_password_sha1(password)
        assert result == expected

    def test_hash_password_sha1_too_long_raises_error(self):
        """Test that overly long password raises ValidationError."""
        password = "a" * 1025
        with pytest.raises(ValidationError, match="exceeds maximum"):
            hash_password_sha1(password)


class TestKAnonymityParts:
    """Tests for k-anonymity hash splitting."""

    def test_get_k_anonymity_parts(self):
        """Test splitting hash into prefix and suffix."""
        hash_value = "ABCDE1234567890ABCDEF"
        prefix, suffix = get_k_anonymity_parts(hash_value)
        assert prefix == "ABCDE"
        assert suffix == "1234567890ABCDEF"

    def test_get_k_anonymity_parts_exact_length(self):
        """Test with exactly 5 character hash."""
        hash_value = "ABCDE"
        prefix, suffix = get_k_anonymity_parts(hash_value)
        assert prefix == "ABCDE"
        assert suffix == ""

    def test_get_k_anonymity_parts_too_short_raises_error(self):
        """Test that short hash raises error."""
        with pytest.raises(ValidationError, match="Invalid hash length"):
            get_k_anonymity_parts("ABCD")


class TestMaskPassword:
    """Tests for password masking."""

    def test_mask_password_short(self):
        """Test masking short password."""
        assert mask_password("abc") == "***"

    def test_mask_password_medium(self):
        """Test masking medium password."""
        result = mask_password("password123", visible_chars=2)
        assert result == "pa*******23"

    def test_mask_password_long(self):
        """Test masking long password."""
        result = mask_password("mypassword12345", visible_chars=3)
        assert result == "myp*******345"

    def test_mask_password_custom_visible(self):
        """Test with custom visible character count."""
        result = mask_password("secret", visible_chars=1)
        assert result == "s****t"


class TestFormatBreachCount:
    """Tests for breach count formatting."""

    def test_format_zero_breaches(self):
        """Test formatting zero breaches."""
        assert format_breach_count(0) == "No breaches found"

    def test_format_one_breach(self):
        """Test formatting single breach."""
        assert format_breach_count(1) == "1 breach"

    def test_format_small_number(self):
        """Test formatting small breach count."""
        assert format_breach_count(500) == "500 breaches"

    def test_format_thousands(self):
        """Test formatting thousands."""
        assert format_breach_count(1500) == "1.5K breaches"
        assert format_breach_count(999999) == "1000.0K breaches"

    def test_format_millions(self):
        """Test formatting millions."""
        assert format_breach_count(1500000) == "1.5M breaches"
        assert format_breach_count(10000000) == "10.0M breaches"


class TestTruncateString:
    """Tests for string truncation."""

    def test_truncate_short_string(self):
        """Test short string doesn't get truncated."""
        assert truncate_string("hello", max_length=10) == "hello"

    def test_truncate_long_string(self):
        """Test long string gets truncated."""
        result = truncate_string("hello world this is a test", max_length=15)
        assert result == "hello world ..."
        assert len(result) == 15

    def test_truncate_exact_length(self):
        """Test string at exact max length."""
        assert truncate_string("hello", max_length=5) == "hello"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_hash_case_sensitivity(self):
        """Test that hashing is case sensitive."""
        hash1 = hash_password_sha1("Password")
        hash2 = hash_password_sha1("password")
        assert hash1 != hash2

    def test_hash_consistency(self):
        """Test that same password produces same hash."""
        hash1 = hash_password_sha1("test123")
        hash2 = hash_password_sha1("test123")
        assert hash1 == hash2
