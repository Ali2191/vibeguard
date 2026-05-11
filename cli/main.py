import os
import click
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from core.scanner import scan_path

console = Console()

SEVERITY_COLORS = {
    'critical': 'bold red',
    'high':     'yellow',
    'medium':   'bold blue',
    'low':      'dim',
}

@click.group()
def cli():
    pass

@cli.command()
@click.argument('path')
@click.option('--json-out', is_flag=True, help='Output raw JSON')
@click.option('--fix', is_flag=True, help='Generate fix suggestions')
@click.option('--no-ai', is_flag=True, help='Use built-in static fixes instead of Gemini API')
@click.option('--only', default=None, type=click.Choice(['critical','high','medium','low']), help='Filter by severity')
@click.option('--report', is_flag=True, help='Generate HTML report file')
def scan(path, json_out, fix, no_ai, only, report):
    """Scan a directory for vibe-code security vulnerabilities."""
    console.print(Panel.fit(
        "[bold]VibeGuard[/bold] — AI-generated code security scanner",
        border_style="dim"
    ))
    console.print(f"\n[dim]Scanning:[/dim] {path}\n")

    with console.status("[dim]Running pattern checks...[/dim]"):
        results = scan_path(path)

    findings = results['findings']

    if only:
        findings = [f for f in findings if f['severity'] == only]

    use_ai = not no_ai

    if fix and findings:
        from models.gemini_explainer import explain_all
        if use_ai:
            console.print(f"[dim]Generating AI fix suggestions for {len(findings)} findings (2s delay between calls)...[/dim]\n")
        else:
            console.print(f"[dim]Applying built-in fix suggestions for {len(findings)} findings...[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Asking Gemini..." if use_ai else "Applying fixes...",
                total=len(findings)
            )
            def tick(done, total):
                progress.update(task, completed=done)
            findings = explain_all(findings, use_ai=use_ai, progress_callback=tick)

        results['findings'] = findings
        console.print()

    if report:
        from output.report import generate_html_report
        import webbrowser
        report_path = os.path.abspath("vibeguard-report.html")
        generate_html_report(results, output_path=report_path)
        console.print(f"\n[bold green]Report saved:[/bold green] {report_path}")
        webbrowser.open(f"file://{report_path}")

    if json_out:
        click.echo(json.dumps(results, indent=2))
        return

    summary = results['summary']
    console.print(
        f"[dim]Files scanned:[/dim] {results['files_scanned']}  "
        f"[bold red]Critical: {summary['critical']}[/bold red]  "
        f"[yellow]High: {summary['high']}[/yellow]  "
        f"[bold blue]Medium: {summary['medium']}[/bold blue]  "
        f"[dim]Low: {summary['low']}[/dim]\n"
    )

    if not findings:
        console.print("[bold green]No issues found.[/bold green]")
        return

    if fix:
        _print_fix_view(findings, path)
    else:
        _print_table_view(findings, path)

    if not fix:
        console.print(f"\n[dim]Tip: run with --fix --no-ai for instant fixes, or --fix for AI-powered suggestions.[/dim]")

def _print_table_view(findings, path):
    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold",
        expand=True
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("File",     style="dim",  max_width=35)
    table.add_column("Line",     width=6)
    table.add_column("Issue",    min_width=30)
    table.add_column("Snippet",  max_width=40, style="dim")

    for f in findings:
        severity = f['severity']
        color = SEVERITY_COLORS.get(severity, 'white')
        relative = f['file'].replace(path, '').lstrip('/')
        snippet = f.get('snippet', '')
        table.add_row(
            f"[{color}]{severity.upper()}[/{color}]",
            relative,
            str(f['line']),
            f['title'],
            snippet[:60] + '...' if len(snippet) > 60 else snippet
        )
    console.print(table)

def _print_fix_view(findings, path):
    for f in findings:
        severity = f['severity']
        color = SEVERITY_COLORS.get(severity, 'white')
        relative = f['file'].replace(path, '').lstrip('/')
        example = f.get('example', '')
        example_block = f"\n[bold]Example fix:[/bold]\n[green]{example}[/green]" if example else ""

        console.print(Panel(
            f"[{color}][bold]{severity.upper()}[/bold][/{color}]  "
            f"[dim]{relative}[/dim]  line [bold]{f['line']}[/bold]\n\n"
            f"[bold]{f['title']}[/bold]\n\n"
            f"[dim]Snippet:[/dim] {f.get('snippet','')[:100]}\n\n"
            f"[bold yellow]Why it matters:[/bold yellow] {f.get('why', '—')}\n\n"
            f"[bold green]Fix:[/bold green] {f.get('fix', '—')}"
            f"{example_block}",
            border_style=color.replace('bold ', ''),
            expand=False
        ))
        console.print()

if __name__ == '__main__':
    cli()
