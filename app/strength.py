"""
Password strength scoring module.

Scores passwords on a scale of 0-100 based on multiple factors:
- Length
- Character variety (uppercase, lowercase, digits, symbols)
- Pattern analysis
- Common password checks
"""

import re
from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple


class StrengthLevel(Enum):
    """Password strength levels."""
    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    GOOD = 3
    STRONG = 4
    VERY_STRONG = 5


@dataclass
class StrengthFeedback:
    """Feedback item with message and severity."""
    message: str
    is_positive: bool = False


@dataclass
class StrengthResult:
    """Complete password strength analysis result."""
    score: int  # 0-100
    level: StrengthLevel
    feedback: List[StrengthFeedback]
    length_score: int
    variety_score: int
    pattern_score: int

    @property
    def level_name(self) -> str:
        """Get human-readable level name."""
        names = {
            StrengthLevel.VERY_WEAK: "Very Weak",
            StrengthLevel.WEAK: "Weak",
            StrengthLevel.FAIR: "Fair",
            StrengthLevel.GOOD: "Good",
            StrengthLevel.STRONG: "Strong",
            StrengthLevel.VERY_STRONG: "Very Strong",
        }
        return names.get(self.level, "Unknown")


class PasswordStrengthAnalyzer:
    """
    Analyzes password strength and provides scoring.

    Scoring breakdown:
    - Length: 0-40 points
    - Character variety: 0-30 points
    - Pattern analysis: 0-30 points
    """

    # Common weak passwords to check against
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'letmein', 'welcome', 'monkey', 'dragon', 'master',
        'admin', 'login', 'user', 'test', 'password123',
        '1234567890', '111111', '555555', 'iloveyou', 'princess',
        'sunshine', 'football', 'baseball', 'trustno1', 'superman'
    }

    def __init__(self):
        """Initialize the strength analyzer."""
        self.feedback: List[StrengthFeedback] = []

    def analyze(self, password: str) -> StrengthResult:
        """
        Analyze password and return strength score.

        Args:
            password: The password to analyze

        Returns:
            StrengthResult with complete analysis
        """
        self.feedback = []

        if not password:
            return StrengthResult(
                score=0,
                level=StrengthLevel.VERY_WEAK,
                feedback=[StrengthFeedback("Password is empty")],
                length_score=0,
                variety_score=0,
                pattern_score=0
            )

        # Calculate component scores
        length_score = self._calculate_length_score(password)
        variety_score = self._calculate_variety_score(password)
        pattern_score = self._calculate_pattern_score(password)

        # Total score
        total_score = min(100, length_score + variety_score + pattern_score)

        # Determine strength level
        level = self._get_strength_level(total_score)

        # Build feedback if score is low
        if total_score < 60:
            self._add_improvement_suggestions(password)

        return StrengthResult(
            score=total_score,
            level=level,
            feedback=self.feedback,
            length_score=length_score,
            variety_score=variety_score,
            pattern_score=pattern_score
        )

    def _calculate_length_score(self, password: str) -> int:
        """
        Calculate length-based score (0-40 points).

        Scoring:
        - Base 5 points for any password
        - +5 per 4 characters up to 40 points
        - Bonus for very long passwords
        """
        length = len(password)
        score = 5  # Base score

        # Additional points for length
        if length >= 8:
            score += 5
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        if length >= 20:
            score += 10

        # Cap at 40
        return min(40, score)

    def _calculate_variety_score(self, password: str) -> int:
        """
        Calculate character variety score (0-30 points).

        Scoring:
        - Each character type: 7 points
        - Bonus for all 4 types: +2
        """
        score = 0
        char_types = 0

        if re.search(r'[a-z]', password):
            score += 7
            char_types += 1
        else:
            self.feedback.append(StrengthFeedback("Add lowercase letters"))

        if re.search(r'[A-Z]', password):
            score += 7
            char_types += 1
        else:
            self.feedback.append(StrengthFeedback("Add uppercase letters"))

        if re.search(r'\d', password):
            score += 7
            char_types += 1
        else:
            self.feedback.append(StrengthFeedback("Add numbers"))

        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password):
            score += 7
            char_types += 1
        else:
            self.feedback.append(StrengthFeedback("Add special characters (!@#$ etc.)"))

        # Bonus for having all character types
        if char_types == 4:
            score += 2
            self.feedback.append(StrengthFeedback("Great character variety!", is_positive=True))

        return min(30, score)

    def _calculate_pattern_score(self, password: str) -> int:
        """
        Calculate pattern-based score (0-30 points).

        Detects and penalizes weak patterns.
        """
        score = 30  # Start full, deduct for issues
        password_lower = password.lower()

        # Check for common passwords
        if password_lower in self.COMMON_PASSWORDS:
            score -= 25
            self.feedback.append(StrengthFeedback("This is a very common password - easily guessed!"))

        # Check for sequential characters
        if self._has_sequential_chars(password):
            score -= 10
            self.feedback.append(StrengthFeedback("Avoid sequential characters (abc, 123)"))

        # Check for repeated characters
        if self._has_repeated_chars(password):
            score -= 10
            self.feedback.append(StrengthFeedback("Avoid repeated characters (aaa, 111)"))

        # Check for keyboard patterns
        if self._has_keyboard_pattern(password_lower):
            score -= 10
            self.feedback.append(StrengthFeedback("Avoid keyboard patterns (qwerty, asdf)"))

        # Check for dictionary words (simplified check)
        if self._has_common_words(password_lower):
            score -= 5
            self.feedback.append(StrengthFeedback("Avoid common words"))

        return max(0, score)

    def _has_sequential_chars(self, password: str, length: int = 3) -> bool:
        """Check for sequential characters (abc, 123, etc.)."""
        for i in range(len(password) - length + 1):
            seq = password[i:i + length]
            if seq.isdigit():
                # Check numeric sequence
                if all(ord(seq[j+1]) - ord(seq[j]) == 1 for j in range(len(seq) - 1)):
                    return True
            elif seq.isalpha():
                # Check alphabetic sequence
                seq_lower = seq.lower()
                if all(ord(seq_lower[j+1]) - ord(seq_lower[j]) == 1 for j in range(len(seq) - 1)):
                    return True
        return False

    def _has_repeated_chars(self, password: str, min_repeat: int = 3) -> bool:
        """Check for repeated characters (aaa, 111, etc.)."""
        pattern = re.compile(r'(.)(\1{' + str(min_repeat - 1) + ',})')
        return bool(pattern.search(password))

    def _has_keyboard_pattern(self, password: str) -> bool:
        """Check for common keyboard patterns."""
        patterns = [
            'qwerty', 'asdf', 'zxcv', 'qazwsx', 'password',
            'letmein', 'welcome', 'admin', 'login'
        ]
        return any(p in password for p in patterns)

    def _has_common_words(self, password: str) -> bool:
        """Simple check for common dictionary words."""
        common_words = [
            'password', 'secret', 'admin', 'login', 'user', 'test',
            'hello', 'world', 'welcome', 'monkey', 'dragon',
            'master', 'shadow', 'sunshine', 'princess', 'football'
        ]
        return any(word in password for word in common_words)

    def _get_strength_level(self, score: int) -> StrengthLevel:
        """Map score to strength level."""
        if score < 20:
            return StrengthLevel.VERY_WEAK
        elif score < 40:
            return StrengthLevel.WEAK
        elif score < 60:
            return StrengthLevel.FAIR
        elif score < 80:
            return StrengthLevel.GOOD
        elif score < 95:
            return StrengthLevel.STRONG
        else:
            return StrengthLevel.VERY_STRONG

    def _add_improvement_suggestions(self, password: str) -> None:
        """Add general improvement suggestions if score is low."""
        if len(password) < 12:
            self.feedback.append(StrengthFeedback("Use at least 12 characters for better security"))


def score_password(password: str) -> int:
    """
    Quick function to get password strength score.

    Args:
        password: Password to score

    Returns:
        Score from 0-100
    """
    analyzer = PasswordStrengthAnalyzer()
    result = analyzer.analyze(password)
    return result.score


def get_strength_level_name(score: int) -> str:
    """
    Get strength level name from score.

    Args:
        score: Score from 0-100

    Returns:
        Human-readable strength level
    """
    analyzer = PasswordStrengthAnalyzer()
    level = analyzer._get_strength_level(score)
    names = {
        StrengthLevel.VERY_WEAK: "Very Weak",
        StrengthLevel.WEAK: "Weak",
        StrengthLevel.FAIR: "Fair",
        StrengthLevel.GOOD: "Good",
        StrengthLevel.STRONG: "Strong",
        StrengthLevel.VERY_STRONG: "Very Strong",
    }
    return names.get(level, "Unknown")
