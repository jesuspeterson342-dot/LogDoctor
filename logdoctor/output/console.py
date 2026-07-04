"""Rich console output for terminal display."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from logdoctor.models import ScanResult, Severity
from logdoctor.utils.perf import BenchmarkResult
from logdoctor.utils.time_utils import format_duration_ms

if TYPE_CHECKING:
    from rich.console import Console

SEVERITY_COLORS = {
    Severity.LOW: "dim",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

SEVERITY_ICONS = {
    Severity.LOW: "○",
    Severity.MEDIUM: "◆",
    Severity.HIGH: "▲",
    Severity.CRITICAL: "✖",
}


def severity_label(severity: Severity) -> Text:
    """Create a styled severity label."""
    color = SEVERITY_COLORS[severity]
    icon = SEVERITY_ICONS[severity]
    return Text(f" {icon} {severity.value.upper()} ", style=color)


def print_scan_result(result: ScanResult, console: Console, verbose: bool = False) -> None:
    """Print a scan result summary and event table to the console."""
    summary = Text()
    summary.append("File: ", style="bold")
    summary.append(f"{result.file_path}\n")
    summary.append("Type: ", style="bold")
    summary.append(f"{result.log_type.value}\n")
    summary.append("Lines: ", style="bold")
    summary.append(f"{result.total_lines}\n")
    summary.append("Duration: ", style="bold")
    summary.append(f"{format_duration_ms(result.duration_ms)}\n")

    counts_line = Text()
    counts_line.append("Critical: ", style="bold red")
    counts_line.append(f"{result.critical_count}  ")
    counts_line.append("Errors: ", style="bold red")
    counts_line.append(f"{result.errors_count}  ")
    counts_line.append("Warnings: ", style="bold yellow")
    counts_line.append(f"{result.warnings_count}")

    console.print(
        Panel(
            Text.assemble(summary, "\n", counts_line),
            title="[bold]Scan Result[/bold]",
            border_style="blue",
        )
    )

    if result.top_patterns:
        table = Table(title="Top Patterns", show_lines=True)
        table.add_column("Rule", style="bold")
        table.add_column("Severity")
        table.add_column("Count", justify="right")
        table.add_column("Description")

        for pat in result.top_patterns[:20]:
            table.add_row(
                pat.name,
                severity_label(pat.severity),
                str(pat.count),
                pat.description,
            )
        console.print(table)

    if result.matched_events:
        total = len(result.matched_events)
        max_display = total if verbose else min(30, total)
        title = f"Events ({max_display}/{total})"
        events_table = Table(title=title, show_lines=True)
        events_table.add_column("#", justify="right", style="dim")
        events_table.add_column("Severity")
        events_table.add_column("Message")

        for event in result.matched_events[:max_display]:
            events_table.add_row(
                str(event.line_number),
                severity_label(event.severity),
                event.message[:120],
            )

        if not verbose and total > 30:
            remaining = total - 30
            hint = f"[{remaining} more events. Use --verbose to see all.]"
            events_table.add_row("...", Text(""), Text(hint))

        console.print(events_table)


def print_rules_list(rules: list, console: Console) -> None:  # type: ignore[type-arg]
    """Print a table of loaded rules."""
    table = Table(title="Active Rules", show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Pattern")

    for rule in rules:
        pat = rule.pattern[:50] + "..." if len(rule.pattern) > 50 else rule.pattern
        table.add_row(
            rule.id,
            rule.name,
            severity_label(rule.severity),
            rule.category,
            pat,
        )

    console.print(table)


def print_benchmark_result(result: BenchmarkResult, console: Console) -> None:
    """Print benchmark results."""
    table = Table(title="Benchmark Result", show_lines=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("File", str(result.file_path))
    table.add_row("Total lines", f"{result.total_lines:,}")
    table.add_row("Events found", f"{result.events_found:,}")
    table.add_row("Elapsed time", f"{result.elapsed_ms:.0f}ms")
    table.add_row("Lines/second", f"{result.lines_per_second:,.0f}")
    table.add_row("Memory peak", str(result.memory_human))

    console.print(table)


def print_error(message: str, console: Console) -> None:
    """Print an error message in a red panel."""
    console.print(Panel(Text(message, style="bold red"), title="Error", border_style="red"))
