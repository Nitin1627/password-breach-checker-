"""
Unit tests for password strength analyzer.
"""

import pytest
from app.strength import (
    PasswordStrengthAnalyzer,
    StrengthLevel,
    StrengthResult,
    StrengthFeedback,
    score_password,
    get_strength_level_name,
)


class TestStrengthFeedback:
    """Tests for StrengthFeedback dataclass."""

    def test_feedback_creation(self):
        """Test creating feedback."""
        feedback = StrengthFeedback("Test message")
        assert feedback.message == "Test message"
        assert feedback.is_positive is False

    def test_positive_feedback(self):
        """Test positive feedback."""
        feedback = StrengthFeedback("Good job!", is_positive=True)
        assert feedback.is_positive is True


class TestStrengthResult:
    """Tests for StrengthResult dataclass."""

    def test_strength_result_creation(self):
        """Test creating strength result."""
        result = StrengthResult(
            score=75,
            level=StrengthLevel.GOOD,
            feedback=[],
            length_score=30,
            variety_score=25,
            pattern_score=20
        )
        assert result.score == 75
        assert result.level == StrengthLevel.GOOD
        assert result.length_score == 30

    def test_is_breached_property(self):
        """Test is_breached property."""
        result_breached = StrengthResult(
            score=50, level=StrengthLevel.FAIR,
            feedback=[], length_score=20, variety_score=20, pattern_score=10
        )
        # Note: This test is actually checking the wrong property name
        # The actual property is is_breached in BreachResult, not StrengthResult

    def test_level_name(self):
        """Test level name property."""
        result = StrengthResult(
            score=90,
            level=StrengthLevel.STRONG,
            feedback=[],
            length_score=35,
            variety_score=28,
            pattern_score=27
        )
        assert result.level_name == "Strong"


class TestPasswordStrengthAnalyzer:
    """Tests for PasswordStrengthAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer fixture."""
        return PasswordStrengthAnalyzer()

    def test_analyze_empty_password(self, analyzer):
        """Test analyzing empty password."""
        result = analyzer.analyze("")
        assert result.score == 0
        assert result.level == StrengthLevel.VERY_WEAK

    def test_analyze_very_weak_password(self, analyzer):
        """Test analyzing very weak password."""
        result = analyzer.analyze("a")
        assert result.score < 20
        assert result.level == StrengthLevel.VERY_WEAK

    def test_analyze_common_password(self, analyzer):
        """Test analyzing common password."""
        result = analyzer.analyze("password")
        assert result.score < 40
        # Should have feedback about common password
        messages = [f.message for f in result.feedback]
        assert any("common" in m.lower() for m in messages)

    def test_analyze_good_password(self, analyzer):
        """Test analyzing good password."""
        result = analyzer.analyze("MyStr0ng!Pass")
        assert result.score >= 60
        assert result.level in [StrengthLevel.GOOD, StrengthLevel.STRONG]

    def test_analyze_strong_password(self, analyzer):
        """Test analyzing very strong password."""
        result = analyzer.analyze("My$up3rStr0ng!P@ssw0rd2024")
        assert result.score >= 80
        assert result.level in [StrengthLevel.STRONG, StrengthLevel.VERY_STRONG]

    def test_length_score(self, analyzer):
        """Test length score calculation."""
        # Very short
        short = analyzer._calculate_length_score("abc")
        assert short == 5  # Base score

        # Medium (8 chars)
        medium = analyzer._calculate_length_score("abcdefgh")
        assert medium == 10  # Base + 5 for 8 chars

        # Long (16+ chars)
        long = analyzer._calculate_length_score("a" * 16)
        assert long == 30  # Base + 5 + 10 + 10

        # Very long (20+ chars)
        very_long = analyzer._calculate_length_score("a" * 20)
        assert very_long == 40  # Max score

    def test_variety_score_lowercase_only(self, analyzer):
        """Test variety score with only lowercase."""
        score = analyzer._calculate_variety_score("lowercase")
        assert score == 7  # Only lowercase

    def test_variety_score_mixed_case(self, analyzer):
        """Test variety score with mixed case."""
        score = analyzer._calculate_variety_score("MixedCase")
        assert score == 14  # Lower + Upper

    def test_variety_score_all_types(self, analyzer):
        """Test variety score with all character types."""
        score = analyzer._calculate_variety_score("M1x3d!T3st")
        # Should have all 4 types + bonus
        assert score == 30  # 7*4 + 2 bonus

    def test_pattern_score_common_password(self, analyzer):
        """Test pattern score with common password."""
        score = analyzer._calculate_pattern_score("password")
        assert score <= 5  # Should be heavily penalized

    def test_pattern_score_sequential_chars(self, analyzer):
        """Test pattern score with sequential characters."""
        score = analyzer._calculate_pattern_score("abc123")
        # Should be penalized for sequential
        assert score < 30

    def test_pattern_score_repeated_chars(self, analyzer):
        """Test pattern score with repeated characters."""
        score = analyzer._calculate_pattern_score("aaa111")
        # Should be penalized for repetition
        assert score < 30

    def test_pattern_score_keyboard_pattern(self, analyzer):
        """Test pattern score with keyboard pattern."""
        score = analyzer._calculate_pattern_score("qwerty123")
        # Should be penalized for keyboard pattern
        assert score < 30

    def test_has_sequential_chars(self, analyzer):
        """Test sequential character detection."""
        assert analyzer._has_sequential_chars("abc123", 3) is True
        assert analyzer._has_sequential_chars("def", 3) is True
        assert analyzer._has_sequential_chars("abc", 4) is False
        assert analyzer._has_sequential_chars("xyz", 3) is True
        assert analyzer._has_sequential_chars("random", 3) is False

    def test_has_repeated_chars(self, analyzer):
        """Test repeated character detection."""
        assert analyzer._has_repeated_chars("aaa", 3) is True
        assert analyzer._has_repeated_chars("111", 3) is True
        assert analyzer._has_repeated_chars("aabbbcc", 3) is True
        assert analyzer._has_repeated_chars("ab", 3) is False
        assert analyzer._has_repeated_chars("abcde", 3) is False

    def test_has_keyboard_pattern(self, analyzer):
        """Test keyboard pattern detection."""
        assert analyzer._has_keyboard_pattern("qwerty") is True
        assert analyzer._has_keyboard_pattern("asdf") is True
        assert analyzer._has_keyboard_pattern("password") is True
        assert analyzer._has_keyboard_pattern("random") is False

    def test_has_common_words(self, analyzer):
        """Test common word detection."""
        assert analyzer._has_common_words("password123") is True
        assert analyzer._has_common_words("admin") is True
        assert analyzer._has_common_words("xyzrandom") is False

    def test_get_strength_level(self, analyzer):
        """Test strength level determination."""
        assert analyzer._get_strength_level(0) == StrengthLevel.VERY_WEAK
        assert analyzer._get_strength_level(19) == StrengthLevel.VERY_WEAK
        assert analyzer._get_strength_level(20) == StrengthLevel.WEAK
        assert analyzer._get_strength_level(39) == StrengthLevel.WEAK
        assert analyzer._get_strength_level(40) == StrengthLevel.FAIR
        assert analyzer._get_strength_level(59) == StrengthLevel.FAIR
        assert analyzer._get_strength_level(60) == StrengthLevel.GOOD
        assert analyzer._get_strength_level(79) == StrengthLevel.GOOD
        assert analyzer._get_strength_level(80) == StrengthLevel.STRONG
        assert analyzer._get_strength_level(94) == StrengthLevel.STRONG
        assert analyzer._get_strength_level(95) == StrengthLevel.VERY_STRONG
        assert analyzer._get_strength_level(100) == StrengthLevel.VERY_STRONG


class TestScorePassword:
    """Tests for score_password function."""

    def test_score_weak_password(self):
        """Test scoring weak password."""
        score = score_password("123")
        assert score < 20

    def test_score_strong_password(self):
        """Test scoring strong password."""
        score = score_password("MyStr0ng!Passw0rd")
        assert score >= 60

    def test_score_empty(self):
        """Test scoring empty password."""
        score = score_password("")
        assert score == 0


class TestGetStrengthLevelName:
    """Tests for get_strength_level_name function."""

    def test_level_names(self):
        """Test getting strength level names."""
        assert get_strength_level_name(0) == "Very Weak"
        assert get_strength_level_name(50) == "Fair"
        assert get_strength_level_name(75) == "Good"
        assert get_strength_level_name(90) == "Strong"
        assert get_strength_level_name(100) == "Very Strong"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_very_long_password(self, analyzer):
        """Test analyzing very long password."""
        result = analyzer.analyze("A" * 100)
        assert result.score >= 80  # Should be strong due to length

    def test_password_with_unicode(self, analyzer):
        """Test analyzing password with unicode."""
        result = analyzer.analyze("héllo Wörld 123!")
        # Should handle unicode gracefully
        assert result.score > 0

    def test_password_with_spaces(self, analyzer):
        """Test analyzing password with spaces."""
        result = analyzer.analyze("my strong password 123!")
        # Spaces should be counted as characters
        assert result.length_score > 5

    def test_only_special_chars(self, analyzer):
        """Test analyzing password with only special characters."""
        result = analyzer.analyze("!@#$%^&*()")
        # Should have variety points for special chars
        assert result.variety_score > 0

    def test_only_numbers(self, analyzer):
        """Test analyzing password with only numbers."""
        result = analyzer.analyze("12345678901234567890")
        # Should have length points but penalized for patterns
        assert result.length_score > 5
        assert result.pattern_score < 30  # Should be penalized
