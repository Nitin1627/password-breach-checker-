"""
Unit tests for CLI module.
"""

import sys
import pytest
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

from cli import (
    create_parser,
    get_password_from_args,
    check_password,
    main,
)
from app.checker import BreachResult
from app.strength import StrengthResult, StrengthLevel


class TestCreateParser:
    """Tests for argument parser creation."""

    def test_parser_creation(self):
        """Test parser is created with expected arguments."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "password-breach-checker"

    def test_password_argument(self):
        """Test --password argument."""
        parser = create_parser()
        args = parser.parse_args(["--password", "test123"])
        assert args.password == "test123"

    def test_file_argument(self):
        """Test --file argument."""
        parser = create_parser()
        args = parser.parse_args(["--file", "password.txt"])
        assert args.file == "password.txt"

    def test_no_breach_flag(self):
        """Test --no-breach flag."""
        parser = create_parser()
        args = parser.parse_args(["--no-breach"])
        assert args.no_breach is True

    def test_strength_only_flag(self):
        """Test --strength-only flag."""
        parser = create_parser()
        args = parser.parse_args(["--strength-only"])
        assert args.strength_only is True

    def test_show_password_flag(self):
        """Test --show-password flag."""
        parser = create_parser()
        args = parser.parse_args(["--show-password"])
        assert args.show_password is True

    def test_simple_flag(self):
        """Test --simple flag."""
        parser = create_parser()
        args = parser.parse_args(["--simple"])
        assert args.simple is True

    def test_timeout_argument(self):
        """Test --timeout argument."""
        parser = create_parser()
        args = parser.parse_args(["--timeout", "60"])
        assert args.timeout == 60

    def test_default_timeout(self):
        """Test default timeout value."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.timeout == 30

    def test_yes_flag(self):
        """Test -y flag."""
        parser = create_parser()
        args = parser.parse_args(["-y"])
        assert args.yes is True

    def test_verbose_flag(self):
        """Test -v flag."""
        parser = create_parser()
        args = parser.parse_args(["-v"])
        assert args.verbose is True

    def test_version_flag(self):
        """Test --version flag."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_password_file_mutual_exclusion(self):
        """Test that password and file arguments are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--password", "test", "--file", "file.txt"])


class TestGetPasswordFromArgs:
    """Tests for getting password from arguments."""

    def test_get_password_from_password_arg(self):
        """Test getting password from --password argument."""
        parser = create_parser()
        args = parser.parse_args(["--password", "mysecret"])
        password = get_password_from_args(args)
        assert password == "mysecret"

    def test_get_password_from_file(self, tmp_path):
        """Test getting password from file."""
        password_file = tmp_path / "password.txt"
        password_file.write_text("filepassword\n")

        parser = create_parser()
        args = parser.parse_args(["--file", str(password_file)])
        password = get_password_from_args(args)
        assert password == "filepassword"

    def test_get_password_from_file_not_found(self, capsys):
        """Test file not found error."""
        parser = create_parser()
        args = parser.parse_args(["--file", "nonexistent.txt"])

        with pytest.raises(SystemExit) as exc_info:
            get_password_from_args(args)
        assert exc_info.value.code == 1

    def test_get_password_none_when_interactive(self):
        """Test returning None for interactive mode."""
        parser = create_parser()
        args = parser.parse_args([])
        password = get_password_from_args(args)
        assert password is None


class TestCheckPassword:
    """Tests for check_password function."""

    @pytest.fixture
    def mock_args(self):
        """Create mock arguments."""
        args = Mock()
        args.no_breach = False
        args.strength_only = False
        args.show_password = False
        args.verbose = False
        args.timeout = 30
        return args

    @pytest.fixture
    def mock_formatter(self):
        """Create mock formatter."""
        return Mock()

    @pytest.fixture
    def mock_breach_result(self):
        """Create mock breach result."""
        result = Mock(spec=BreachResult)
        result.is_breached = False
        result.breach_count = 0
        return result

    @pytest.fixture
    def mock_strength_result(self):
        """Create mock strength result."""
        result = Mock(spec=StrengthResult)
        result.score = 75
        result.level = StrengthLevel.GOOD
        result.feedback = []
        return result

    @patch('cli.BreachChecker')
    def test_check_password_success(
        self,
        mock_checker_class,
        mock_args,
        mock_formatter,
        mock_breach_result,
        mock_strength_result
    ):
        """Test successful password check."""
        mock_checker = Mock()
        mock_checker.__enter__ = Mock(return_value=mock_checker)
        mock_checker.__exit__ = Mock(return_value=None)
        mock_checker.check_password.return_value = mock_breach_result
        mock_checker_class.return_value = mock_checker

        with patch('cli.PasswordStrengthAnalyzer') as mock_analyzer_class:
            mock_analyzer = Mock()
            mock_analyzer.analyze.return_value = mock_strength_result
            mock_analyzer_class.return_value = mock_analyzer

            exit_code = check_password("testpass", mock_args, mock_formatter)
            assert exit_code == 0

    @patch('cli.BreachChecker')
    def test_check_password_breached(
        self,
        mock_checker_class,
        mock_args,
        mock_formatter,
        mock_strength_result
    ):
        """Test check when password is breached."""
        mock_breach_result = Mock(spec=BreachResult)
        mock_breach_result.is_breached = True
        mock_breach_result.breach_count = 5

        mock_checker = Mock()
        mock_checker.__enter__ = Mock(return_value=mock_checker)
        mock_checker.__exit__ = Mock(return_value=None)
        mock_checker.check_password.return_value = mock_breach_result
        mock_checker_class.return_value = mock_checker

        with patch('cli.PasswordStrengthAnalyzer') as mock_analyzer_class:
            mock_analyzer = Mock()
            mock_analyzer.analyze.return_value = mock_strength_result
            mock_analyzer_class.return_value = mock_analyzer

            exit_code = check_password("testpass", mock_args, mock_formatter)
            assert exit_code == 1  # Returns 1 when breached

    def test_check_password_offline_mode(
        self,
        mock_args,
        mock_formatter,
        mock_strength_result
    ):
        """Test offline mode."""
        mock_args.no_breach = True

        with patch('cli.check_breach_offline') as mock_offline:
            mock_offline.return_value = Mock(
                spec=BreachResult,
                is_breached=False,
                breach_count=-1
            )

            with patch('cli.PasswordStrengthAnalyzer') as mock_analyzer_class:
                mock_analyzer = Mock()
                mock_analyzer.analyze.return_value = mock_strength_result
                mock_analyzer_class.return_value = mock_analyzer

                exit_code = check_password("testpass", mock_args, mock_formatter)
                assert exit_code == 0
                mock_offline.assert_called_once_with("testpass")


class TestMain:
    """Tests for main function."""

    @patch('cli.get_password_secure')
    @patch('cli.check_password')
    @patch('cli.ReportFormatter')
    def test_main_interactive_mode(
        self,
        mock_formatter_class,
        mock_check,
        mock_get_password
    ):
        """Test main function in interactive mode."""
        mock_get_password.return_value = "mypassword"
        mock_check.return_value = 0

        with patch('sys.argv', ['cli.py']):
            exit_code = main()
            assert exit_code == 0
            mock_get_password.assert_called_once()

    @patch('cli.check_password')
    def test_main_with_password_arg(self, mock_check):
        """Test main with --password argument."""
        mock_check.return_value = 0

        with patch('sys.argv', ['cli.py', '--password', 'test123']):
            exit_code = main()
            assert exit_code == 0

    @patch('cli.ReportFormatter')
    def test_main_empty_password(self, mock_formatter_class):
        """Test main with empty password."""
        mock_formatter = Mock()
        mock_formatter_class.return_value = mock_formatter

        with patch('sys.argv', ['cli.py', '--password', '']):
            exit_code = main()
            assert exit_code == 1

    @patch('cli.get_password_secure')
    def test_main_keyboard_interrupt(self, mock_get_password):
        """Test main with keyboard interrupt."""
        mock_get_password.side_effect = KeyboardInterrupt()

        with patch('sys.argv', ['cli.py']):
            exit_code = main()
            assert exit_code == 130

    @patch('cli.confirm_action')
    @patch('cli.get_password_secure')
    @patch('cli.check_password')
    def test_main_confirm_no(
        self,
        mock_check,
        mock_get_password,
        mock_confirm
    ):
        """Test main when user declines confirmation."""
        mock_get_password.return_value = "mypassword"
        mock_confirm.return_value = False

        with patch('sys.argv', ['cli.py']):
            exit_code = main()
            assert exit_code == 0
            mock_confirm.assert_called_once()


class TestEdgeCases:
    """Tests for edge cases."""

    def test_parser_help(self, capsys):
        """Test help message."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(['--help'])

    def test_long_password_validation(self):
        """Test validation of overly long password."""
        parser = create_parser()
        long_password = "a" * 1025

        with patch('sys.argv', ['cli.py', '--password', long_password]):
            with patch('cli.ReportFormatter') as mock_formatter_class:
                mock_formatter = Mock()
                mock_formatter_class.return_value = mock_formatter

                exit_code = main()
                assert exit_code == 1

    def test_verbose_mode_shows_info(self):
        """Test verbose mode displays info messages."""
        parser = create_parser()
        args = parser.parse_args(['-v'])
        assert args.verbose is True

    @patch('cli.check_password')
    @patch('cli.SimpleReportFormatter')
    def test_simple_output_mode(self, mock_formatter_class, mock_check):
        """Test simple output mode."""
        mock_check.return_value = 0
        mock_formatter = Mock()
        mock_formatter_class.return_value = mock_formatter

        with patch('sys.argv', ['cli.py', '--password', 'test', '--simple']):
            exit_code = main()
            assert exit_code == 0
