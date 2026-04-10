#!/usr/bin/env python3
"""
Password Breach Checker CLI

A modular CLI tool for checking password breaches using the
HaveIBeenPwned API with k-anonymity.

Usage:
    python cli.py
    python cli.py --password "mysecret123"
    python cli.py --no-breach --show-password
"""

import sys
import argparse
from typing import Optional

from app.checker import BreachChecker, check_breach_offline
from app.strength import PasswordStrengthAnalyzer
from app.report import ReportFormatter, SimpleReportFormatter
from app.utils import (
    get_password_secure,
    confirm_action,
    ValidationError,
)
from app.checker import APIError, NetworkError


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser.

    Returns:
        Configured ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="password-breach-checker",
        description="Check if passwords have been exposed in data breaches using HIBP API",
        epilog="Uses k-anonymity: only first 5 chars of SHA1 hash are sent to API",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Password input options
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument(
        "-p", "--password",
        type=str,
        metavar="PASSWORD",
        help="Password to check (not recommended - use interactive mode)"
    )
    password_group.add_argument(
        "-f", "--file",
        type=str,
        metavar="FILE",
        help="Read password from file (first line only)"
    )

    # Mode options
    parser.add_argument(
        "--no-breach",
        action="store_true",
        help="Skip breach check, analyze password strength only (offline mode)"
    )

    parser.add_argument(
        "--strength-only",
        action="store_true",
        help="Alias for --no-breach"
    )

    # Display options
    parser.add_argument(
        "--show-password",
        action="store_true",
        help="Display the password in output (default: masked)"
    )

    parser.add_argument(
        "--simple",
        action="store_true",
        help="Use simple text output instead of Rich formatting"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    # API options
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="API request timeout in seconds (default: 30)"
    )

    # Other options
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompt"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )

    return parser


def get_password_from_args(args) -> Optional[str]:
    """
    Get password from various input sources.

    Args:
        args: Parsed command line arguments

    Returns:
        Password string or None
    """
    # From direct argument (not recommended)
    if args.password:
        return args.password

    # From file
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                return f.readline().strip()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        except IOError as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)

    # Interactive mode
    return None


def check_password(
    password: str,
    args,
    formatter: ReportFormatter
) -> int:
    """
    Check password breach status and display results.

    Args:
        password: Password to check
        args: Command line arguments
        formatter: Output formatter

    Returns:
        Exit code (0 = success, 1 = breached/error)
    """
    # Analyze password strength first (always done)
    if args.verbose:
        formatter.display_info("Analyzing password strength...")

    analyzer = PasswordStrengthAnalyzer()
    strength_result = analyzer.analyze(password)

    # Check for breach (unless offline mode)
    breach_result = None
    offline_mode = args.no_breach or args.strength_only

    if offline_mode:
        if args.verbose:
            formatter.display_info("Offline mode: Skipping breach check")
        breach_result = check_breach_offline(password)
    else:
        if args.verbose:
            formatter.display_info("Checking HaveIBeenPwned database...")

        try:
            with BreachChecker(timeout=args.timeout) as checker:
                breach_result = checker.check_password(password)
        except APIError as e:
            formatter.display_error(f"API Error: {e}")
            return 1
        except NetworkError as e:
            formatter.display_error(f"Network Error: {e}")
            formatter.display_info("Use --no-breach for offline strength analysis only")
            return 1
        except ValidationError as e:
            formatter.display_error(f"Validation Error: {e}")
            return 1
        except Exception as e:
            formatter.display_error(f"Unexpected error: {e}")
            return 1

    # Display results
    formatter.display_result(
        password=password,
        breach_result=breach_result,
        strength_result=strength_result,
        show_password=args.show_password
    )

    # Return appropriate exit code
    if breach_result.is_breached:
        return 1  # Breached - security concern

    return 0  # Success


def main() -> int:
    """
    Main entry point for CLI.

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args()

    # Create formatter
    use_rich = not args.simple
    formatter = ReportFormatter() if use_rich else SimpleReportFormatter()

    # Get password
    password = get_password_from_args(args)

    # If no password provided, use interactive mode
    if password is None:
        try:
            password = get_password_secure("Enter password to check: ")
        except KeyboardInterrupt:
            print("\nCancelled.", file=sys.stderr)
            return 130

        if not password:
            formatter.display_error("Password cannot be empty")
            return 1

        # Confirm for security (unless -y flag)
        if not args.yes:
            print()
            masked = '*' * len(password)
            print(f"Password entered: {masked} ({len(password)} characters)")

            if not confirm_action("Continue with this password?"):
                formatter.display_info("Cancelled")
                return 0

    # Validate password
    if len(password) > 1024:
        formatter.display_error("Password too long (max 1024 characters)")
        return 1

    # Run check
    try:
        return check_password(password, args, formatter)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
