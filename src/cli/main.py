"""Main CLI entry point."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from sqlalchemy.orm import Session

from src.core.database import SessionLocal, init_db
from src.core.logger import configure_logging, get_logger
from src.core.models import ScanStatus
from src.core.scanner import SecurityScanner

console = Console()
logger = get_logger(__name__)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.pass_context
def cli(ctx, verbose):
    """Security Automation Platform CLI."""
    configure_logging()
    if verbose:
        import logging

        logging.getLogger().setLevel(logging.DEBUG)
    ctx.ensure_object(dict)


@cli.command()
@click.option("--target", default="localhost", help="Target system to scan")
@click.option(
    "--type",
    "scan_type",
    type=click.Choice(["full", "compliance", "vulnerability", "config"]),
    default="full",
    help="Type of scan to perform",
)
@click.option("--framework", multiple=True, help="Compliance frameworks to check (e.g., cis)")
@click.option("--output", "-o", type=click.Path(), help="Output file for results (JSON)")
@click.option("--format", "output_format", type=click.Choice(["json", "table", "csv"]), default="table")
def scan(target, scan_type, framework, output, output_format):
    """Run a security scan."""
    console.print(f"[bold green]Starting {scan_type} scan on {target}[/bold green]")

    # Initialize database
    init_db()

    # Create scanner
    db_session = SessionLocal()
    try:
        scanner = SecurityScanner(db_session=db_session)
        scan_result = scanner.scan(
            target=target,
            scan_type=scan_type,
            compliance_frameworks=list(framework) if framework else None,
        )

        # Display results
        if output_format == "table":
            _display_scan_results_table(scan_result, db_session)
        elif output_format == "json":
            results_json = _get_scan_results_json(scan_result, db_session)
            if output:
                with open(output, "w") as f:
                    json.dump(results_json, f, indent=2)
                console.print(f"[green]Results saved to {output}[/green]")
            else:
                console.print(json.dumps(results_json, indent=2))
        elif output_format == "csv":
            _display_scan_results_csv(scan_result, db_session, output)

        console.print(f"[bold green]Scan completed: {scan_result.status.value}[/bold green]")
    finally:
        db_session.close()


@cli.command()
@click.option("--framework", type=click.Choice(["cis", "nist", "custom"]), default="cis", help="Compliance framework")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
def compliance(framework, output):
    """Check compliance against security frameworks."""
    console.print(f"[bold green]Checking {framework.upper()} compliance[/bold green]")

    init_db()
    db_session = SessionLocal()
    try:
        scanner = SecurityScanner(db_session=db_session)
        scan_result = scanner.scan(target="localhost", scan_type="compliance", compliance_frameworks=[framework])

        if scan_result.status == ScanStatus.COMPLETED:
            console.print("[green]Compliance check completed[/green]")
        else:
            console.print(f"[red]Compliance check failed: {scan_result.error_message}[/red]")
            sys.exit(1)
    finally:
        db_session.close()


@cli.command()
@click.option("--package", help="Specific package to scan")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
def vulnerability(package, output):
    """Scan for vulnerabilities."""
    console.print("[bold green]Scanning for vulnerabilities[/bold green]")

    init_db()
    db_session = SessionLocal()
    try:
        scanner = SecurityScanner(db_session=db_session)
        scan_type = "vulnerability" if not package else "vulnerability"
        scan_result = scanner.scan(target="localhost", scan_type=scan_type)

        if scan_result.status == ScanStatus.COMPLETED:
            console.print("[green]Vulnerability scan completed[/green]")
        else:
            console.print(f"[red]Vulnerability scan failed: {scan_result.error_message}[/red]")
            sys.exit(1)
    finally:
        db_session.close()


@cli.command()
@click.option("--scan-id", type=int, help="Scan ID to generate report for")
@click.option("--format", "report_format", type=click.Choice(["json", "csv", "pdf"]), default="json")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
def report(scan_id, report_format, output):
    """Generate a security report."""
    console.print("[bold green]Generating security report[/bold green]")

    init_db()
    db_session = SessionLocal()
    try:
        scanner = SecurityScanner(db_session=db_session)
        if scan_id:
            results = scanner.get_scan_results(scan_id)
            if results:
                console.print(f"[green]Report generated for scan {scan_id}[/green]")
            else:
                console.print(f"[red]Scan {scan_id} not found[/red]")
                sys.exit(1)
        else:
            console.print("[yellow]Please specify --scan-id[/yellow]")
            sys.exit(1)
    finally:
        db_session.close()


def _display_scan_results_table(scan_result, db_session: Session):
    """Display scan results in a table format."""
    table = Table(title=f"Scan Results - {scan_result.target}")

    table.add_column("ID", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("Findings", style="yellow")
    table.add_column("Started", style="blue")

    table.add_row(
        str(scan_result.id),
        scan_result.status.value,
        scan_result.scan_type,
        str(len(scan_result.findings)),
        scan_result.started_at.strftime("%Y-%m-%d %H:%M:%S") if scan_result.started_at else "N/A",
    )

    console.print(table)

    # Display findings if any
    if scan_result.findings:
        findings_table = Table(title="Security Findings")
        findings_table.add_column("Severity", style="red")
        findings_table.add_column("Title", style="white")
        findings_table.add_column("Category", style="cyan")

        for finding in scan_result.findings[:10]:  # Show first 10
            findings_table.add_row(
                finding.severity.value.upper(),
                finding.title[:50],
                finding.category,
            )

        console.print(findings_table)

        if len(scan_result.findings) > 10:
            console.print(f"[yellow]... and {len(scan_result.findings) - 10} more findings[/yellow]")


def _get_scan_results_json(scan_result, db_session: Session) -> dict:
    """Get scan results as JSON."""
    return {
        "scan_id": scan_result.id,
        "target": scan_result.target,
        "scan_type": scan_result.scan_type,
        "status": scan_result.status.value,
        "started_at": scan_result.started_at.isoformat() if scan_result.started_at else None,
        "completed_at": scan_result.completed_at.isoformat() if scan_result.completed_at else None,
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "recommendation": f.recommendation,
            }
            for f in scan_result.findings
        ],
        "compliance_results": [
            {
                "framework": c.framework,
                "rule_id": c.rule_id,
                "rule_name": c.rule_name,
                "passed": bool(c.passed),
                "description": c.description,
                "remediation": c.remediation,
            }
            for c in scan_result.compliance_results
        ],
    }


def _display_scan_results_csv(scan_result, db_session: Session, output: Optional[Path]):
    """Display scan results in CSV format."""
    import csv

    if not output:
        console.print("[red]CSV format requires --output option[/red]")
        return

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Title", "Severity", "Category", "CVE ID", "CVSS Score", "Recommendation"])

        for finding in scan_result.findings:
            writer.writerow(
                [
                    finding.title,
                    finding.severity.value,
                    finding.category,
                    finding.cve_id or "",
                    finding.cvss_score or "",
                    finding.recommendation or "",
                ]
            )

    console.print(f"[green]CSV report saved to {output}[/green]")


if __name__ == "__main__":
    cli()

