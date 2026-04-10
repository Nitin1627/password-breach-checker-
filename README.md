# Password Breach Checker

A modular Python CLI tool for checking if passwords have been exposed in data breaches using the [HaveIBeenPwned](https://haveibeenpwned.com/) API with **k-anonymity**.

## Features

- **Secure Breach Checking**: Uses k-anonymity - only sends first 5 characters of SHA1 hash to API
- **Password Strength Analysis**: Scores passwords 0-100 based on length, variety, and patterns
- **Rich Console Output**: Beautiful formatted reports with color-coded results
- **Offline Mode**: Analyze password strength without network connection
- **Secure Input**: Passwords entered via secure prompt (no echo)
- **Comprehensive Testing**: Full pytest unit test coverage

## Architecture

```
password-breach-checker/
├── app/
│   ├── __init__.py       # Package initialization
│   ├── checker.py        # HIBP API integration with k-anonymity
│   ├── strength.py       # Password strength scoring
│   ├── report.py         # Rich console formatting
│   └── utils.py          # Utility functions
├── tests/
│   ├── __init__.py
│   ├── test_checker.py   # Breach checker tests
│   ├── test_strength.py  # Strength analyzer tests
│   ├── test_utils.py     # Utility function tests
│   └── test_cli.py       # CLI tests
├── cli.py                # Main CLI entry point
├── requirements.txt      # Dependencies
└── README.md
```

## Installation

```bash
# Clone or download the project
cd password-breach-checker

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Interactive Mode (Recommended)

```bash
python cli.py
```

You'll be prompted to enter a password securely (hidden input).

### Command Line Arguments

```bash
# Check a password directly (not recommended - visible in shell history)
python cli.py --password "mysecretpassword"

# Read password from file
python cli.py --file password.txt

# Offline mode (strength analysis only)
python cli.py --no-breach

# Show password in output (default: masked)
python cli.py --show-password

# Simple text output (no colors)
python cli.py --simple

# Custom timeout
python cli.py --timeout 60

# Skip confirmation prompt
python cli.py -y

# Verbose output
python cli.py -v
```

### Examples

```bash
# Standard check
$ python cli.py
Enter password to check:
Password entered: ******** (12 characters)
Continue with this password? [y/N]: y
[Displays full report]

# Offline strength analysis
$ python cli.py --no-breach
Enter password to check:
[Shows strength analysis without breach check]

# Simple output mode
$ python cli.py --simple
Enter password to check:
[Plain text output without colors]
```

## How It Works

### K-Anonymity Protocol

This tool uses the k-anonymity model to check passwords without exposing them:

1. **SHA1 Hash**: Your password is hashed locally using SHA1
2. **Prefix Only**: Only the first 5 characters of the hash are sent to HIBP API
3. **Local Comparison**: The API returns suffixes matching that prefix, which are compared locally
4. **Breach Count**: If your full hash matches, the breach count is returned

**Example:**
```
Password: "password"
SHA1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8

Sent to API: 5BAA6
API Response: Contains 1E4C9B93F3F0682250B6CF8331B7EE68FD8:3820001
Result: Password found in 3,820,001 breaches!
```

### Password Strength Scoring

Scores are calculated 0-100 based on:

| Factor | Max Points | Criteria |
|--------|-----------|----------|
| **Length** | 40 | +5 for 8+ chars, +10 for 12+, +10 for 16+, +10 for 20+ |
| **Variety** | 30 | +7 each for lowercase, uppercase, digits, special chars |
| **Patterns** | 30 | Penalties for common passwords, sequences, repetitions |

**Strength Levels:**
- 0-19: Very Weak (🔴)
- 20-39: Weak (🟠)
- 40-59: Fair (🟡)
- 60-79: Good (🟢)
- 80-94: Strong (🔒)
- 95-100: Very Strong (🔐)

## Testing

Run the complete test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_checker.py

# Run with verbose output
pytest -v
```

### Test Coverage

- `test_checker.py`: API integration, k-anonymity, error handling
- `test_strength.py`: Password scoring, pattern detection
- `test_utils.py`: Utility functions, secure input
- `test_cli.py`: CLI argument parsing, main flow

## Security Considerations

- ✅ Passwords are never sent in full to any external service
- ✅ Uses k-anonymity to protect password privacy
- ✅ Secure input handling with `getpass` (no echo)
- ✅ Passwords are masked in output by default
- ✅ No password logging or storage
- ✅ Local hashing before any network requests

## API Rate Limits

The HIBP API is rate-limited. If you receive rate limit errors:

1. Wait a few minutes before retrying
2. Use `--no-breach` for offline strength analysis
3. The tool will display appropriate error messages

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, password not breached |
| 1 | Password breached or error occurred |
| 130 | Interrupted by user (Ctrl+C) |

## Dependencies

- **requests**: HTTP library for API calls
- **rich**: Beautiful console output and formatting
- **pytest**: Testing framework

## License

This is a defensive security tool for educational purposes.

## Credits

- Uses the [HaveIBeenPwned](https://haveibeenpwned.com/) API by Troy Hunt
- Built with [Rich](https://github.com/Textualize/rich) for console output

## Contributing

This is a demonstration project showcasing:
- Clean modular architecture
- Secure API integration
- Comprehensive testing
- CLI design patterns
- Type hints and documentation
