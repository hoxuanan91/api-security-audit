#!/usr/bin/env python3
"""
API Security Audit Tool
Scans REST APIs against OWASP API Security Top 10 (2023).

Usage:
    python main.py --config examples/sample_config.yaml
    python main.py --url https://api.example.com --token mytoken --endpoints /users /products
    python main.py --config examples/sample_config.yaml --output report.json
"""
import sys

# Force UTF-8 output on Windows so unicode characters render correctly
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from audit.core.config import ScanConfig
from audit.core.scanner import run
from audit.core.report import print_report, export_json

console = Console()


@click.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to YAML config file")
@click.option("--url", "-u", help="Base URL of the API to scan")
@click.option("--token", "-t", help="Bearer token for authentication")
@click.option("--endpoints", "-e", multiple=True, help="Endpoints to scan (e.g. /api/users)")
@click.option("--output", "-o", help="Export findings to a JSON file")
@click.option("--no-ssl-verify", is_flag=True, default=False, help="Disable SSL certificate verification")
def main(config, url, token, endpoints, output, no_ssl_verify):
    """API Security Audit Tool — OWASP API Top 10 scanner."""

    if config:
        scan_config = ScanConfig.from_yaml(config)
    elif url:
        scan_config = ScanConfig(
            base_url=url.rstrip("/"),
            token=token,
            endpoints=list(endpoints),
            verify_ssl=not no_ssl_verify,
        )
    else:
        console.print("[red]Error:[/red] Provide either --config or --url")
        sys.exit(1)

    console.print(f"\n[bold]Target:[/bold] {scan_config.base_url}")
    console.print(f"[bold]Endpoints:[/bold] {scan_config.endpoints or ['(base URL only)']}")
    auth_label = "[green]yes — token provided[/green]" if scan_config.token else "[dim]no token[/dim]"
    console.print(f"[bold]Auth:[/bold] {auth_label}\n")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Scanning...", total=None)

        def on_progress(check_name: str):
            progress.update(task, description=f"Running: {check_name}")

        result = run(scan_config, progress_callback=on_progress)

    print_report(result)

    if output:
        export_json(result, output)


if __name__ == "__main__":
    main()
