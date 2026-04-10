"""
Unit tests for breach checker module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from app.checker import (
    BreachChecker,
    BreachResult,
    check_breach_offline,
    APIError,
    NetworkError,
    BreachCheckerError,
)
from app.utils import ValidationError


class TestBreachResult:
    """Tests for BreachResult class."""

    def test_breach_result_creation(self):
        """Test creating BreachResult."""
        result = BreachResult(
            password_hash="ABC123DEF456",
            breach_count=5,
            suffix_matched="123DEF456"
        )
        assert result.password_hash == "ABC123DEF456"
        assert result.breach_count == 5
        assert result.suffix_matched == "123DEF456"
        assert result.prefix == "ABC12"
        assert result.suffix == "3DEF456"

    def test_is_breached_true(self):
        """Test is_breached property when breached."""
        result = BreachResult(password_hash="ABC123", breach_count=1)
        assert result.is_breached is True

    def test_is_breached_false(self):
        """Test is_breached property when not breached."""
        result = BreachResult(password_hash="ABC123", breach_count=0)
        assert result.is_breached is False

    def test_repr(self):
        """Test string representation."""
        result = BreachResult(password_hash="ABC123", breach_count=5)
        repr_str = repr(result)
        assert "breach_count=5" in repr_str
        assert "is_breached=True" in repr_str


class TestBreachChecker:
    """Tests for BreachChecker class."""

    def test_init(self):
        """Test initialization."""
        checker = BreachChecker(timeout=60)
        assert checker.timeout == 60
        assert checker._session is None

    def test_get_session(self):
        """Test session creation."""
        checker = BreachChecker()
        session = checker._get_session()
        assert session is not None
        assert checker._session is session
        # Second call should return same session
        assert checker._get_session() is session

    def test_close(self):
        """Test session closing."""
        checker = BreachChecker()
        checker._get_session()  # Create session
        checker.close()
        assert checker._session is None

    def test_context_manager(self):
        """Test context manager usage."""
        with BreachChecker() as checker:
            assert checker._session is not None
        assert checker._session is None

    @patch('app.checker.requests.Session')
    def test_query_hibp_api_success(self, mock_session_class):
        """Test successful API query."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "ABC123:5\nDEF456:10"

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        checker = BreachChecker()
        checker._session = mock_session

        response = checker._query_hibp_api("ABC12")
        assert response.status_code == 200
        assert response.text == "ABC123:5\nDEF456:10"

    @patch('app.checker.requests.Session')
    def test_query_hibp_api_rate_limit(self, mock_session_class):
        """Test API rate limit handling."""
        mock_response = Mock()
        mock_response.status_code = 429

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        checker = BreachChecker()
        checker._session = mock_session

        with pytest.raises(APIError, match="Rate limited"):
            checker._query_hibp_api("ABC12")

    @patch('app.checker.requests.Session')
    def test_query_hibp_api_other_error(self, mock_session_class):
        """Test API other error handling."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Server Error"

        mock_session = Mock()
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        checker = BreachChecker()
        checker._session = mock_session

        with pytest.raises(APIError, match="500"):
            checker._query_hibp_api("ABC12")

    def test_find_breach_count_found(self):
        """Test finding breach count when suffix exists."""
        checker = BreachChecker()
        response_text = "ABC123:5\nDEF456:10\nGHI789:15"
        count = checker._find_breach_count(response_text, "DEF456")
        assert count == 10

    def test_find_breach_count_not_found(self):
        """Test finding breach count when suffix doesn't exist."""
        checker = BreachChecker()
        response_text = "ABC123:5\nDEF456:10"
        count = checker._find_breach_count(response_text, "XYZ999")
        assert count == 0

    def test_find_breach_count_malformed_lines(self):
        """Test handling malformed API response lines."""
        checker = BreachChecker()
        response_text = "ABC123:5\nMALFORMED\nDEF456:10\n:invalid\n"
        count = checker._find_breach_count(response_text, "DEF456")
        assert count == 10

    def test_find_breach_count_empty_response(self):
        """Test handling empty response."""
        checker = BreachChecker()
        count = checker._find_breach_count("", "DEF456")
        assert count == 0

    @patch.object(BreachChecker, '_query_hibp_api')
    def test_check_password_success_not_breached(self, mock_query):
        """Test checking password not in breach database."""
        mock_response = Mock()
        mock_response.text = "OTHER123:5\nANOTHER:10"
        mock_query.return_value = mock_response

        checker = BreachChecker()
        result = checker.check_password("testpassword123")

        assert result.breach_count == 0
        assert result.is_breached is False

    @patch.object(BreachChecker, '_query_hibp_api')
    def test_check_password_success_breached(self, mock_query):
        """Test checking password found in breach database."""
        # Calculate expected hash and suffix
        import hashlib
        password = "testpassword123"
        full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = full_hash[:5]
        suffix = full_hash[5:]

        # Mock response with matching suffix
        mock_response = Mock()
        mock_response.text = f"OTHER:5\n{suffix}:42\nANOTHER:10"
        mock_query.return_value = mock_response

        checker = BreachChecker()
        result = checker.check_password(password)

        assert result.breach_count == 42
        assert result.is_breached is True

    def test_check_password_empty_raises_error(self):
        """Test that empty password raises ValidationError."""
        checker = BreachChecker()
        with pytest.raises(ValidationError):
            checker.check_password("")


class TestOfflineMode:
    """Tests for offline mode."""

    def test_check_breach_offline(self):
        """Test offline breach check."""
        result = check_breach_offline("testpassword")

        assert result.breach_count == -1  # -1 indicates unknown/offline
        assert result.is_breached is False  # Not technically breached
        assert result.password_hash is not None
        assert len(result.password_hash) == 40  # SHA1 hex length

    def test_offline_result_has_prefix_suffix(self):
        """Test offline result has prefix and suffix."""
        result = check_breach_offline("mypassword")
        assert len(result.prefix) == 5
        assert len(result.suffix) == 35


class TestErrorHandling:
    """Tests for error handling."""

    def test_api_error_inheritance(self):
        """Test APIError inherits from BreachCheckerError."""
        assert issubclass(APIError, BreachCheckerError)

    def test_network_error_inheritance(self):
        """Test NetworkError inherits from BreachCheckerError."""
        assert issubclass(NetworkError, BreachCheckerError)

    @patch.object(BreachChecker, '_query_hibp_api')
    def test_network_error_on_timeout(self, mock_query):
        """Test NetworkError raised on timeout."""
        import requests
        mock_query.side_effect = requests.exceptions.Timeout()

        checker = BreachChecker()
        with pytest.raises(NetworkError, match="timed out"):
            checker.check_password("test")

    @patch.object(BreachChecker, '_query_hibp_api')
    def test_network_error_on_connection(self, mock_query):
        """Test NetworkError raised on connection error."""
        import requests
        mock_query.side_effect = requests.exceptions.ConnectionError("No connection")

        checker = BreachChecker()
        with pytest.raises(NetworkError, match="Connection failed"):
            checker.check_password("test")
