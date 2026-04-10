"""
Breach checker module for HaveIBeenPwned API.

Uses k-anonymity to check passwords without exposing the full hash.
"""

import requests
from typing import Optional
from .utils import (
    HIBP_API_URL,
    REQUEST_TIMEOUT,
    get_k_anonymity_parts,
    hash_password_sha1,
    ValidationError,
)


class BreachCheckerError(Exception):
    """Base exception for breach checker errors."""
    pass


class APIError(BreachCheckerError):
    """Raised when HIBP API request fails."""
    pass


class NetworkError(BreachCheckerError):
    """Raised when network request fails."""
    pass


class BreachResult:
    """Result of a breach check."""

    def __init__(self, password_hash: str, breach_count: int, suffix_matched: str = ""):
        self.password_hash = password_hash
        self.breach_count = breach_count
        self.suffix_matched = suffix_matched
        self.prefix, self.suffix = get_k_anonymity_parts(password_hash)

    @property
    def is_breached(self) -> bool:
        """Check if password was found in any breach."""
        return self.breach_count > 0

    def __repr__(self) -> str:
        return f"BreachResult(breach_count={self.breach_count}, is_breached={self.is_breached})"


class BreachChecker:
    """
    Checker for password breaches using HaveIBeenPwned API.

    Uses k-anonymity: only sends first 5 characters of SHA1 hash.
    The API returns suffixes matching that prefix, which are
    compared locally to find the full hash match.
    """

    def __init__(self, timeout: int = REQUEST_TIMEOUT):
        """
        Initialize breach checker.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self._session: Optional[requests.Session] = None

    def _get_session(self) -> requests.Session:
        """Get or create requests session for connection pooling."""
        if self._session is None:
            self._session = requests.Session()
            # Add headers to identify client and support compression
            self._session.headers.update({
                "User-Agent": "PasswordBreachChecker-CLI/1.0",
                "Accept": "application/json",
            })
        return self._session

    def check_password(self, password: str) -> BreachResult:
        """
        Check if password exists in breach database.

        Args:
            password: Plain text password to check

        Returns:
            BreachResult with breach count

        Raises:
            ValidationError: If password is invalid
            APIError: If API request fails
            NetworkError: If network connection fails
        """
        # Hash the password
        password_hash = hash_password_sha1(password)
        prefix, suffix = get_k_anonymity_parts(password_hash)

        # Query API with k-anonymity
        try:
            response = self._query_hibp_api(prefix)
        except requests.exceptions.Timeout:
            raise NetworkError(f"Request timed out after {self.timeout} seconds")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"Connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise APIError(f"API request failed: {e}")

        # Parse response and find matching suffix
        breach_count = self._find_breach_count(response.text, suffix)

        return BreachResult(
            password_hash=password_hash,
            breach_count=breach_count,
            suffix_matched=suffix if breach_count > 0 else ""
        )

    def _query_hibp_api(self, prefix: str) -> requests.Response:
        """
        Query HIBP API with hash prefix.

        Args:
            prefix: First 5 characters of SHA1 hash

        Returns:
            API response

        Raises:
            APIError: If API returns error status
            requests.exceptions.RequestException: For network errors
        """
        url = HIBP_API_URL.format(prefix)
        session = self._get_session()

        response = session.get(url, timeout=self.timeout)

        # Handle rate limiting
        if response.status_code == 429:
            raise APIError("Rate limited by HIBP API. Please wait and try again.")

        # Handle other errors
        if response.status_code != 200:
            raise APIError(
                f"HIBP API returned status {response.status_code}: {response.text[:200]}"
            )

        return response

    def _find_breach_count(self, response_text: str, target_suffix: str) -> int:
        """
        Parse API response to find breach count for specific hash suffix.

        The API returns lines in format:
        HASH_SUFFIX:COUNT

        Args:
            response_text: Raw API response text
            target_suffix: The hash suffix to search for

        Returns:
            Breach count (0 if not found)
        """
        target_suffix_upper = target_suffix.upper()

        for line in response_text.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Line format: HASH_SUFFIX:COUNT
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    suffix = parts[0].strip().upper()
                    try:
                        count = int(parts[1].strip())
                        if suffix == target_suffix_upper:
                            return count
                    except ValueError:
                        # Skip malformed lines
                        continue

        return 0

    def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


def check_breach_offline(password: str) -> BreachResult:
    """
    Create a breach result without API call (offline mode).

    Args:
        password: Password to hash

    Returns:
        BreachResult with count=0 (unknown)
    """
    password_hash = hash_password_sha1(password)
    return BreachResult(
        password_hash=password_hash,
        breach_count=-1,  # -1 indicates unknown/offline
        suffix_matched=""
    )
