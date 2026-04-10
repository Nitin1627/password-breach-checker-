"""
Utility functions for password breach checker.

Provides secure input handling, constants, and helper functions.
"""

import getpass
import hashlib
import sys
from typing import Optional


class SecureInputError(Exception):
    """Raised when secure input handling fails."""
    pass


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


# Constants
HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"
REQUEST_TIMEOUT = 30  # seconds
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 1024  # Reasonable limit to prevent abuse


def hash_password_sha1(password: str) -> str:
    """
    Hash password using SHA1 and return uppercase hex digest.

    Args:
        password: The plain text password to hash

    Returns:
        Uppercase SHA1 hash string

    Raises:
        ValidationError: If password is empty or exceeds max length
    """
    if not password:
        raise ValidationError("Password cannot be empty")

    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValidationError(f"Password exceeds maximum length of {MAX_PASSWORD_LENGTH}")

    # SHA1 hash and convert to uppercase hex
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    return sha1_hash


def get_k_anonymity_parts(password_hash: str) -> tuple[str, str]:
    """
    Split SHA1 hash into prefix (first 5 chars) and suffix for k-anonymity.

    Args:
        password_hash: Full SHA1 hash

    Returns:
        Tuple of (prefix, suffix) where prefix is first 5 chars
    """
    if len(password_hash) < 5:
        raise ValidationError("Invalid hash length")

    prefix = password_hash[:5]
    suffix = password_hash[5:]
    return prefix, suffix


def get_password_secure(prompt: str = "Enter password: ") -> str:
    """
    Securely get password input from user without echoing.

    Args:
        prompt: The prompt to display to user

    Returns:
        The password entered by user

    Raises:
        SecureInputError: If input cannot be secured
    """
    try:
        # Use getpass for secure input (no echo)
        password = getpass.getpass(prompt)
        return password
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled by user.", file=sys.stderr)
        sys.exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        raise SecureInputError(f"Failed to get secure input: {e}")


def confirm_action(message: str) -> bool:
    """
    Ask user for confirmation.

    Args:
        message: The confirmation message to display

    Returns:
        True if user confirms, False otherwise
    """
    try:
        response = input(f"{message} [y/N]: ").strip().lower()
        return response in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return False


def mask_password(password: str, visible_chars: int = 2) -> str:
    """
    Mask password for display, showing only first and last few characters.

    Args:
        password: The password to mask
        visible_chars: Number of characters to show at start and end

    Returns:
        Masked password string
    """
    if len(password) <= visible_chars * 2 + 2:
        return "*" * len(password)

    return password[:visible_chars] + "*" * (len(password) - visible_chars * 2) + password[-visible_chars:]


def format_breach_count(count: int) -> str:
    """
    Format breach count with human-readable suffix.

    Args:
        count: Number of breaches

    Returns:
        Formatted string with count
    """
    if count == 0:
        return "No breaches found"
    elif count == 1:
        return "1 breach"
    elif count < 1000:
        return f"{count} breaches"
    elif count < 1000000:
        return f"{count / 1000:.1f}K breaches"
    else:
        return f"{count / 1000000:.1f}M breaches"


def truncate_string(s: str, max_length: int = 50) -> str:
    """
    Truncate string with ellipsis if too long.

    Args:
        s: String to truncate
        max_length: Maximum length

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."
