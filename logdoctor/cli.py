"""CLI application entry point."""

from __future__ import annotations

import signal
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from logdoctor import __version__
from logdoctor.config import (
    copy_default_rules,
    ensure_config_dir,
    load_config,
    write_default_config,
)
from logdoctor.detector import compile_rules, load_rules, match_line
from logdoctor.models import LogType, ScanResult, Severity
from logdoctor.output.console import (
    print_benchmark_result,
    print_error,
    print_rules_list,
    print_scan_result,
)
from logdoctor.output.json_report import generate_json_report
from logdoctor.output.markdown import generate_markdown_report
from logdoctor.parsers import detect_parser_for_file, get_parser
from logdoctor.scanner import scan_file
from logdoctor.utils.file_utils import count_lines, file_size_human, readable
from logdoctor.utils.perf import Benchmark
from logdoctor.utils.time_utils import format_duration_ms

app = typer.Typer(
    name="logdoctor",
    help="Terminal utility for log analysis, error detection, and reporting.",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"logdoctor {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", "-V", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
    color: bool = typer.Option(True, "--color/--no-color", help="Enable/disable colored output."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-essential output."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output."),
) -> None:
    """LogDoctor — analyze logs, find errors, generate reports."""
    global console  # noqa: PLW0603
    console = Console(no_color=not color)


def _resolve_log_type(raw: str | None) -> LogType | None:
    """Parse and validate a log type string."""
    if not raw:
        return None
    try:
        return LogType(raw)
    except ValueError:
        valid = ", ".join(t.value for t in LogType)
        print_error(f"Unknown log type: {raw}. Valid: {valid}", console)
        raise typer.Exit(1) from None


@app.command()
def scan(
    filepath: str = typer.Argument(..., help="Path to the log file."),
    log_type_raw: str | None = typer.Option(
        None, "--type", "-t", help="Force log type.",
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json.",
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Write output to file."),
) -> None:
    """Analyze a log file for errors and patterns."""
    path = Path(filepath)
    if not path.exists():
        print_error(f"File not found: {filepath}", console)
        raise typer.Exit(1)
    if not readable(path):
        print_error(f"Cannot read file: {filepath}", console)
        raise typer.Exit(1)

    log_type = _resolve_log_type(log_type_raw)
    config = load_config()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        result = scan_file(filepath, config, log_type=log_type)
        progress.update(task, description="Done!")

    if output_format == "json":
        report = generate_json_report(result)
        if output:
            Path(output).write_text(report, encoding="utf-8")
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print(report)
    else:
        print_scan_result(result, console, verbose=True)
        if output:
            md = generate_markdown_report(result)
            Path(output).write_text(md, encoding="utf-8")
            console.print(f"[green]Report written to {output}[/green]")


@app.command()
def watch(
    filepath: str = typer.Argument(..., help="Path to the log file to watch."),
    log_type_raw: str | None = typer.Option(None, "--type", "-t", help="Force log type."),
) -> None:
    """Watch a log file in realtime (like tail -f)."""
    path = Path(filepath)
    if not path.exists():
        print_error(f"File not found: {filepath}", console)
        raise typer.Exit(1)

    log_type = _resolve_log_type(log_type_raw)
    config = load_config()
    parser = get_parser(log_type) if log_type else detect_parser_for_file(filepath)
    rules = load_rules(config)
    compiled = compile_rules(rules)

    event_count = 0
    critical_alert = Text("[CRITICAL ALERT]", style="bold red blink")

    def signal_handler(sig: int, frame: object) -> None:
        console.print("\n[dim]Stopped watching.[/dim]")
        console.print(f"Events seen: {event_count}")
        raise typer.Exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    console.print(f"[bold blue]Watching:[/bold blue] {filepath}")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    import time
                    time.sleep(0.3)
                    continue

                line = line.rstrip("\n\r")
                event = parser.parse_line(line, event_count)
                rule_matches = match_line(line, compiled, parser.log_type.value)

                if event is not None:
                    event_count += 1
                    sev = event.severity
                    if sev == Severity.CRITICAL:
                        console.print(critical_alert, end=" ")
                        console.print(f" {event.message}")
                    elif sev == Severity.HIGH:
                        console.print(f"  [red]ERROR[/red] {event.message}")
                    elif sev == Severity.MEDIUM:
                        console.print(f"  [yellow]WARN [/yellow] {event.message}")
                    else:
                        console.print(f"  [dim]{event.message}[/dim]")
                elif rule_matches:
                    event_count += 1
                    for rule in rule_matches:
                        if rule.severity == Severity.CRITICAL:
                            console.print(critical_alert, end=" ")
                            console.print(f" {rule.name}: {line[:100]}")
                        else:
                            console.print(
                                f"  [dim]RULE[/dim] {rule.name}: {line[:100]}",
                            )
                else:
                    console.print(f"  [dim]{line[:120]}[/dim]")

    except FileNotFoundError:
        print_error(f"File disappeared: {filepath}", console)
        raise typer.Exit(1) from None


@app.command()
def report(
    filepath: str = typer.Argument(..., help="Path to the log file."),
    output_format: str = typer.Option(
        "markdown", "--format", "-f", help="Report format: markdown, json, text.",
    ),
    output: str = typer.Option("report.md", "--output", "-o", help="Output file path."),
    log_type_raw: str | None = typer.Option(None, "--type", "-t", help="Force log type."),
) -> None:
    """Generate an analysis report."""
    path = Path(filepath)
    if not path.exists():
        print_error(f"File not found: {filepath}", console)
        raise typer.Exit(1)

    log_type = _resolve_log_type(log_type_raw)
    config = load_config()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Generating report...", total=None)
        result = scan_file(filepath, config, log_type=log_type)

    out_path = Path(output)

    if output_format == "json":
        report_content = generate_json_report(result)
        out_path = out_path.with_suffix(".json")
    elif output_format == "text":
        report_content = _generate_text_report(result)
        out_path = out_path.with_suffix(".txt")
    else:
        report_content = generate_markdown_report(result)
        out_path = out_path.with_suffix(".md")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report_content, encoding="utf-8")
    console.print(f"[green]Report written to {out_path}[/green]")
    console.print(f"  Format: {output_format}")
    console.print(f"  Events: {len(result.matched_events)}")
    console.print(f"  Patterns: {len(result.top_patterns)}")


@app.command("rules")
def rules_cmd(
    action: str = typer.Argument("list", help="Action: list"),
) -> None:
    """Show active analysis rules."""
    if action != "list":
        print_error(f"Unknown action: {action}. Use 'list'.", console)
        raise typer.Exit(1)

    config = load_config()
    rules = load_rules(config)
    if not rules:
        console.print("[dim]No rules found.[/dim]")
        return

    print_rules_list(rules, console)
    console.print(f"\n[dim]Total: {len(rules)} rules[/dim]")


@app.command()
def doctor() -> None:
    """Check environment and configuration."""
    config = load_config()

    table = Table(title="Environment Check", show_lines=True)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 12)
    table.add_row(
        "Python version",
        "[green]OK[/green]" if py_ok else "[red]FAIL[/red]",
        py_ver,
    )

    config_dir = ensure_config_dir()
    table.add_row(
        "Config directory",
        "[green]OK[/green]",
        str(config_dir),
    )

    from logdoctor.config import DEFAULT_CONFIG_FILE
    cfg_exists = DEFAULT_CONFIG_FILE.exists()
    table.add_row(
        "Config file",
        "[green]OK[/green]" if cfg_exists else "[yellow]MISSING[/yellow]",
        str(DEFAULT_CONFIG_FILE),
    )

    from logdoctor.config import get_rules_dir
    rules_dir = get_rules_dir(config)
    rules_ok = rules_dir.exists() and any(rules_dir.glob("*.yml"))
    rules_count = len(list(rules_dir.glob("*.yml"))) if rules_ok else 0
    table.add_row(
        "Rules directory",
        "[green]OK[/green]" if rules_ok else "[red]FAIL[/red]",
        f"{rules_dir} ({rules_count} files)" if rules_ok else str(rules_dir),
    )

    from logdoctor.config import resolve_cache_dir
    cache_dir = resolve_cache_dir(config)
    table.add_row(
        "Cache directory",
        "[green]OK[/green]",
        str(cache_dir),
    )

    rules = load_rules(config)
    table.add_row(
        "Loaded rules",
        f"[green]{len(rules)}[/green]" if rules else "[red]0[/red]",
        f"{len(rules)} rules loaded" if rules else "No rules found",
    )

    log_dirs = [Path("/var/log"), Path("/tmp")]
    for log_dir in log_dirs:
        exists = log_dir.exists()
        table.add_row(
            f"Directory {log_dir}",
            "[green]OK[/green]" if exists else "[yellow]N/A[/yellow]",
            "exists" if exists else "not found",
        )

    console.print(table)


@app.command()
def benchmark(
    filepath: str = typer.Argument(..., help="Path to the log file to benchmark."),
    log_type_raw: str | None = typer.Option(None, "--type", "-t", help="Force log type."),
) -> None:
    """Benchmark scanning speed on a large file."""
    path = Path(filepath)
    if not path.exists():
        print_error(f"File not found: {filepath}", console)
        raise typer.Exit(1)

    config = load_config()
    total_lines = count_lines(path)
    size = file_size_human(path)

    console.print(f"[bold]Benchmarking:[/bold] {filepath}")
    console.print(f"  Size: {size} | Lines: {total_lines:,}")
    console.print()

    log_type = _resolve_log_type(log_type_raw)

    bench = Benchmark(file_path=filepath)
    bench.start()
    result = scan_file(filepath, config, log_type=log_type)
    bench_result = bench.finish(total_lines, len(result.matched_events))
    print_benchmark_result(bench_result, console)


@app.command()
def init() -> None:
    """Initialize default configuration and rules."""
    console.print("[bold]Initializing LogDoctor...[/bold]\n")

    cfg_path = write_default_config()
    console.print(f"[green]Config created:[/green] {cfg_path}")

    from logdoctor.config import DEFAULT_RULES_DIR
    rules_dir = DEFAULT_RULES_DIR.parent / "rules_user"
    written = copy_default_rules(rules_dir)
    console.print(f"[green]Rules copied:[/green] {len(written)} files to {rules_dir}")

    console.print("\n[bold green]Done![/bold green] LogDoctor is ready.")
    console.print(f"  Config: {cfg_path}")
    console.print(f"  Rules:  {rules_dir}")


def _generate_text_report(result: ScanResult) -> str:
    """Generate plain text report."""
    lines = [
        "LogDoctor Report",
        "=" * 40,
        f"File: {result.file_path}",
        f"Type: {result.log_type.value}",
        f"Lines: {result.total_lines}",
        f"Duration: {format_duration_ms(result.duration_ms)}",
        "",
        "Statistics:",
        f"  Critical: {result.critical_count}",
        f"  Errors:   {result.errors_count}",
        f"  Warnings: {result.warnings_count}",
        f"  Total:    {len(result.matched_events)}",
        "",
    ]

    if result.top_patterns:
        lines.append("Top Patterns:")
        for i, p in enumerate(result.top_patterns[:20], 1):
            lines.append(f"  {i}. [{p.severity.value}] {p.name} (x{p.count})")
            if p.description:
                lines.append(f"     {p.description}")
        lines.append("")

    if result.top_patterns:
        lines.append("Recommendations:")
        for p in result.top_patterns:
            if p.recommendation:
                lines.append(f"  - {p.name}: {p.recommendation}")
        lines.append("")

    lines.append("Generated by LogDoctor")
    return "\n".join(lines)


if __name__ == "__main__":
    app()
