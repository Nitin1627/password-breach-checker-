"""
Report formatting module using Rich for beautiful console output.

Provides formatted display for breach check results and password strength.
"""

from typing import Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.text import Text
from rich.style import Style
from rich.align import Align

from .checker import BreachResult
from .strength import StrengthResult, StrengthLevel
from .utils import mask_password, format_breach_count


class ReportFormatter:
    """Formats and displays password check results with Rich."""

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize report formatter.

        Args:
            console: Optional Rich console instance
        """
        self.console = console or Console()

    def display_result(
        self,
        password: str,
        breach_result: BreachResult,
        strength_result: StrengthResult,
        show_password: bool = False
    ) -> None:
        """
        Display complete password check result.

        Args:
            password: The original password (for display purposes)
            breach_result: Breach check result
            strength_result: Strength analysis result
            show_password: Whether to show password or mask it
        """
        # Print header
        self._print_header()

        # Print password info
        self._print_password_info(password, show_password)

        # Print breach status
        self._print_breach_status(breach_result)

        # Print strength analysis
        self._print_strength_analysis(strength_result)

        # Print recommendations
        self._print_recommendations(breach_result, strength_result)

        # Print footer
        self._print_footer()

    def _print_header(self) -> None:
        """Print report header."""
        self.console.print()
        self.console.print(
            Panel.fit(
                "[bold blue]Password Breach Checker[/bold blue]",
                border_style="blue",
                padding=(1, 2)
            )
        )
        self.console.print()

    def _print_password_info(self, password: str, show_password: bool) -> None:
        """Print password information section."""
        display_pwd = password if show_password else mask_password(password)

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style="cyan", justify="right")
        table.add_column("Value", style="white")

        table.add_row("Password:", display_pwd)
        table.add_row("Length:", f"{len(password)} characters")

        self.console.print(table)
        self.console.print()

    def _print_breach_status(self, result: BreachResult) -> None:
        """Print breach check results."""
        if result.breach_count == -1:
            # Offline mode
            self.console.print(
                Panel(
                    "[yellow]! Offline Mode[/yellow]\n"
                    "Breach check skipped. Password strength analysis only.",
                    border_style="yellow",
                    padding=(1, 2)
                )
            )
            return

        if result.is_breached:
            # Breach found
            breach_text = Text()
            breach_text.append("X BREACHED\n", style="bold red")
            breach_text.append(
                f"This password appears in {format_breach_count(result.breach_count)}!",
                style="red"
            )

            self.console.print(
                Panel(
                    breach_text,
                    border_style="red",
                    padding=(1, 2)
                )
            )

            # Show severity
            if result.breach_count > 1000000:
                self.console.print(
                    "[red]! This password is extremely compromised. "
                    "Do NOT use this password anywhere![/red]"
                )
            elif result.breach_count > 10000:
                self.console.print(
                    "[yellow]! This password has been widely compromised. "
                    "Change it immediately if in use.[/yellow]"
                )
        else:
            # No breach
            self.console.print(
                Panel(
                    "[green]+ NOT BREACHED[/green]\n"
                    "This password was not found in any known data breaches.",
                    border_style="green",
                    padding=(1, 2)
                )
            )

        self.console.print()

    def _print_strength_analysis(self, result: StrengthResult) -> None:
        """Print password strength analysis."""
        # Determine color based on score
        if result.score >= 80:
            color = "green"
            emoji = "[*]"
        elif result.score >= 60:
            color = "yellow"
            emoji = "[Y]"
        elif result.score >= 40:
            color = "orange"
            emoji = "🟠"
        else:
            color = "red"
            emoji = "[R]"

        # Create strength panel
        strength_text = Text()
        strength_text.append(f"{emoji} Strength: ", style="bold")
        strength_text.append(f"{result.level_name}", style=f"bold {color}")
        strength_text.append(f" ({result.score}/100)\n\n", style="dim")

        # Add score breakdown
        strength_text.append(f"Length Score: ", style="cyan")
        strength_text.append(f"{result.length_score}/40\n", style="white")

        strength_text.append(f"Variety Score: ", style="cyan")
        strength_text.append(f"{result.variety_score}/30\n", style="white")

        strength_text.append(f"Pattern Score: ", style="cyan")
        strength_text.append(f"{result.pattern_score}/30\n", style="white")

        self.console.print(
            Panel(
                strength_text,
                border_style=color,
                padding=(1, 2),
                title="[bold]Password Strength Analysis[/bold]",
                title_align="left"
            )
        )

        # Print score bar
        self._print_score_bar(result.score, color)
        self.console.print()

        # Print feedback if any
        if result.feedback:
            self._print_feedback(result.feedback)

    def _print_score_bar(self, score: int, color: str) -> None:
        """Print a visual score bar."""
        bar_length = 40
        filled = int((score / 100) * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        self.console.print(f"[{color}]{bar}[/{color}] {score}%")

    def _print_feedback(self, feedback_list: List) -> None:
        """Print strength feedback items."""
        self.console.print("[bold]Suggestions:[/bold]")

        for item in feedback_list:
            if item.is_positive:
                symbol = "+"
                style = "green"
            else:
                symbol = "•"
                style = "yellow"

            self.console.print(f"  [{style}]{symbol}[/{style}] {item.message}")

        self.console.print()

    def _print_recommendations(
        self,
        breach_result: BreachResult,
        strength_result: StrengthResult
    ) -> None:
        """Print security recommendations."""
        recommendations = []

        # Check breach status
        if breach_result.breach_count > 0:
            recommendations.append(
                "[red]• CHANGE THIS PASSWORD IMMEDIATELY[/red] - "
                "It has been exposed in data breaches"
            )

        # Check strength
        if strength_result.score < 60:
            recommendations.append(
                "[yellow]• Use a stronger password[/yellow] - "
                "This password is too weak for secure use"
            )

        if strength_result.score < 80:
            recommendations.append(
                "[cyan]• Consider using a password manager[/cyan] - "
                "Generates and stores strong unique passwords"
            )

        # General recommendations
        recommendations.extend([
            "[dim]• Use unique passwords for each account[/dim]",
            "[dim]• Enable two-factor authentication (2FA) where possible[/dim]",
        ])

        if recommendations:
            self.console.print("[bold]Recommendations:[/bold]")
            for rec in recommendations:
                self.console.print(f"  {rec}")
            self.console.print()

    def _print_footer(self) -> None:
        """Print report footer."""
        self.console.print(
            "[dim]Powered by HaveIBeenPwned API with k-anonymity[/dim]",
            justify="center"
        )
        self.console.print()

    def display_error(self, message: str) -> None:
        """
        Display error message.

        Args:
            message: Error message to display
        """
        self.console.print()
        self.console.print(
            Panel(
                f"[red]X Error[/red]\n{message}",
                border_style="red",
                padding=(1, 2)
            )
        )
        self.console.print()

    def display_warning(self, message: str) -> None:
        """
        Display warning message.

        Args:
            message: Warning message to display
        """
        self.console.print()
        self.console.print(
            Panel(
                f"[yellow]! Warning[/yellow]\n{message}",
                border_style="yellow",
                padding=(1, 2)
            )
        )
        self.console.print()

    def display_info(self, message: str) -> None:
        """
        Display info message.

        Args:
            message: Info message to display
        """
        self.console.print(f"[cyan]ℹ {message}[/cyan]")

    def display_success(self, message: str) -> None:
        """
        Display success message.

        Args:
            message: Success message to display
        """
        self.console.print(f"[green]+ {message}[/green]")


class SimpleReportFormatter:
    """Simple text-based formatter for non-TTY environments."""

    def __init__(self):
        """Initialize simple formatter."""
        pass

    def display_result(
        self,
        password: str,
        breach_result: BreachResult,
        strength_result: StrengthResult,
        show_password: bool = False
    ) -> None:
        """
        Display result in simple text format.

        Args:
            password: Original password
            breach_result: Breach check result
            strength_result: Strength analysis
            show_password: Whether to show password
        """
        display_pwd = password if show_password else mask_password(password)

        print("=" * 50)
        print("PASSWORD BREACH CHECKER")
        print("=" * 50)
        print()

        print(f"Password: {display_pwd}")
        print(f"Length: {len(password)} characters")
        print()

        # Breach status
        if breach_result.breach_count == -1:
            print("BREACH CHECK: Skipped (offline mode)")
        elif breach_result.is_breached:
            print(f"BREACH STATUS: FOUND IN {format_breach_count(breach_result.breach_count)}")
        else:
            print("BREACH STATUS: NOT FOUND")
        print()

        # Strength
        print(f"STRENGTH: {strength_result.level_name} ({strength_result.score}/100)")
        print(f"  - Length Score: {strength_result.length_score}/40")
        print(f"  - Variety Score: {strength_result.variety_score}/30")
        print(f"  - Pattern Score: {strength_result.pattern_score}/30")
        print()

        # Feedback
        if strength_result.feedback:
            print("Suggestions:")
            for item in strength_result.feedback:
                symbol = "[OK]" if item.is_positive else "[-]"
                print(f"  {symbol} {item.message}")
            print()

        print("=" * 50)

    def display_error(self, message: str) -> None:
        """Display error."""
        print(f"ERROR: {message}")

    def display_warning(self, message: str) -> None:
        """Display warning."""
        print(f"WARNING: {message}")

    def display_info(self, message: str) -> None:
        """Display info."""
        print(f"INFO: {message}")

    def display_success(self, message: str) -> None:
        """Display success."""
        print(f"SUCCESS: {message}")


def create_formatter(use_rich: bool = True) -> ReportFormatter:
    """
    Factory function to create appropriate formatter.

    Args:
        use_rich: Whether to use Rich formatting

    Returns:
        Formatter instance
    """
    if use_rich:
        return ReportFormatter()
    else:
        return SimpleReportFormatter()
