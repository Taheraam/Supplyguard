"""SupplyGuard CLI interface powered by Click and Rich.

Exit codes:
    0 — Scan complete, risk score ≤ threshold (pass).
    1 — Scan complete, risk score > threshold (policy violation).
    2 — Scan failed due to tool error.
"""

import concurrent.futures
import datetime
import json
import logging
import shutil
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from supplyguard.config import (
    CONFIG_FILENAME,
    SupplyGuardConfig,
    load_config,
    severity_meets_minimum,
    write_default_config,
)
from supplyguard.formatters import ScanOutput, format_output
from supplyguard.models import Finding, Scan, init_db
from supplyguard.remediation.loop import remediate
from supplyguard.sast.scanner import run_sast
from supplyguard.sbom.generator import generate_sbom
from supplyguard.scoring.engine import calculate_risk_score
from supplyguard.secrets.scanner import scan_secrets
from supplyguard.vulns.osv_client import batch_query

console = Console(stderr=True, force_terminal=True)
logger = logging.getLogger(__name__)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose debug logging.")
@click.version_option(version="0.3.0")
def main(verbose: bool = False) -> None:
    """SupplyGuard — AI-Aware Software Supply Chain Security Scanner & Self-Heal Engine."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s", force=True)


# --------------------------------------------------------------------------- #
# supplyguard init
# --------------------------------------------------------------------------- #


@main.command(name="init")
@click.argument(
    "project_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
def init_cmd(project_path: Path) -> None:
    """Initialize SupplyGuard configuration for a project."""
    console.print()
    console.print("[bold cyan][SHIELD] SupplyGuard Project Setup[/]")
    console.print("─" * 40)

    # Detect project type
    has_requirements = (project_path / "requirements.txt").exists()
    has_pyproject = (project_path / "pyproject.toml").exists()
    has_setup = (project_path / "setup.py").exists()

    if has_requirements or has_pyproject or has_setup:
        console.print("[green]✓[/] Python project detected")
    else:
        console.print("[yellow]![/] No Python project markers found (requirements.txt, pyproject.toml)")

    # Check external tools
    semgrep_path = shutil.which("semgrep")
    gitleaks_path = shutil.which("gitleaks")
    console.print(
        f"[green]✓[/] Semgrep: {'[green]' + semgrep_path + '[/]' if semgrep_path else '[yellow]not found[/] (will use built-in AST scanner)'}"
    )
    console.print(
        f"[green]✓[/] Gitleaks: {'[green]' + gitleaks_path + '[/]' if gitleaks_path else '[yellow]not found[/] (will use built-in regex scanner)'}"
    )

    # Write config
    try:
        config_path = write_default_config(project_path)
        console.print(f"[green]✓[/] Created [bold]{CONFIG_FILENAME}[/] with default configuration")
        console.print(f"  [dim]{config_path}[/]")
    except FileExistsError:
        console.print(f"[yellow]![/] {CONFIG_FILENAME} already exists — skipping")

    console.print()
    console.print("[dim]Run [bold]supplyguard scan .[/] to start your first scan.[/]")


# --------------------------------------------------------------------------- #
# supplyguard scan
# --------------------------------------------------------------------------- #


@main.command(name="scan")
@click.argument(
    "project_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["table", "json", "sarif"], case_sensitive=False),
    default=None,
    help="Output format (default: table, or from .supplyguard.yml).",
)
@click.option(
    "--threshold", "-t",
    type=int,
    default=None,
    help="Risk score threshold. Exits with code 1 if exceeded (default: 100).",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option("--db-path", type=click.Path(path_type=Path), default="supplyguard.db", help="SQLite database path.")
def scan_cmd(
    project_path: Path,
    output_format: str | None,
    threshold: int | None,
    output: Path | None,
    db_path: Path,
) -> None:
    """Scan a project for supply chain vulnerabilities, secrets, and code smells."""
    try:
        _run_scan(project_path, output_format, threshold, output, db_path)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(2)
    except Exception as err:  # noqa: BLE001
        console.print(f"[bold red]Scan failed:[/] {err}")
        logger.exception("Scan failed")
        sys.exit(2)


def _run_scan(
    project_path: Path,
    output_format: str | None,
    threshold: int | None,
    output: Path | None,
    db_path: Path,
) -> None:
    """Internal scan implementation with proper exit codes.

    Args:
        project_path: Target project directory.
        output_format: CLI override for format.
        threshold: CLI override for threshold.
        output: Optional output file path.
        db_path: SQLite database path.
    """
    # Load config (file + CLI overrides)
    cli_overrides = {}
    if output_format is not None:
        cli_overrides["format"] = output_format
    if threshold is not None:
        cli_overrides["threshold"] = threshold

    config = load_config(project_path, cli_overrides)
    resolved_format = config.format
    resolved_threshold = config.threshold

    started_at = datetime.datetime.now(datetime.UTC)

    # Non-table formats should not print progress to stdout
    is_interactive = resolved_format == "table" and output is None

    if is_interactive:
        console.print(f"\n[bold cyan][SCAN] Scanning:[/] {project_path.resolve()}\n")

    # Run scan pipeline with progress indicators
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        disable=not is_interactive,
    ) as progress:
        # 1. SBOM + OSV
        task_sbom = progress.add_task("Generating CycloneDX SBOM...", total=None)
        _, components = generate_sbom(project_path)
        progress.update(task_sbom, description=f"[green]✓[/] SBOM: {len(components)} components")
        progress.stop_task(task_sbom)

        task_osv = progress.add_task(f"Querying OSV.dev ({len(components)} packages)...", total=None)
        vulns = batch_query(components)
        progress.update(task_osv, description=f"[green]✓[/] OSV: {len(vulns)} vulnerabilities found")
        progress.stop_task(task_osv)

        # 2. Parallel Secrets + SAST
        task_parallel = progress.add_task("Running Secrets + SAST scans...", total=None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f_secrets = executor.submit(scan_secrets, project_path)
            f_sast = executor.submit(run_sast, project_path)
            secrets = f_secrets.result()
            sast_findings = f_sast.result()
        progress.update(
            task_parallel,
            description=f"[green]✓[/] Secrets: {len(secrets)} | SAST: {len(sast_findings)} findings",
        )
        progress.stop_task(task_parallel)

    # 3. Scoring
    score_breakdown = calculate_risk_score(vulns, secrets, sast_findings)
    finished_at = datetime.datetime.now(datetime.UTC)

    # 4. Persistence
    _, session_factory = init_db(db_path)
    with session_factory() as session:
        scan_rec = Scan(
            project_path=str(project_path.resolve()),
            started_at=started_at,
            finished_at=finished_at,
            risk_score=score_breakdown.total_score,
            components_count=len(components),
            findings_count=len(vulns) + len(secrets) + len(sast_findings),
        )
        session.add(scan_rec)
        session.flush()

        for v in vulns:
            session.add(
                Finding(
                    scan_id=scan_rec.id,
                    source="sbom_osv",
                    severity=v.severity,
                    file="requirements.txt",
                    line=1,
                    rule_id=v.vuln_id,
                    cwe="CWE-1395",
                    message=f"{v.package}=={v.version}: {v.summary}",
                    raw_json=json.dumps({"package": v.package, "fixed": v.fixed_version}),
                )
            )

        for s in secrets:
            session.add(
                Finding(
                    scan_id=scan_rec.id,
                    source="secrets",
                    severity="CRITICAL",
                    file=s.file,
                    line=s.line,
                    rule_id=s.rule_id,
                    cwe="CWE-798",
                    message=f"Hardcoded secret ({s.rule_id}): {s.match_preview}",
                    raw_json=json.dumps({"match_preview": s.match_preview}),
                )
            )

        for sa in sast_findings:
            session.add(
                Finding(
                    scan_id=scan_rec.id,
                    source="sast",
                    severity=sa.severity,
                    file=sa.file,
                    line=sa.line,
                    rule_id=sa.rule_id,
                    cwe=sa.cwe,
                    message=sa.message,
                    raw_json=json.dumps({"rule_id": sa.rule_id, "cwe": sa.cwe}),
                )
            )

        session.commit()
        scan_id = scan_rec.id

    # 5. Build unified findings list and apply filters
    all_findings: list[dict[str, str | int]] = []

    for v in vulns:
        if not severity_meets_minimum(v.severity, config.severity_minimum):
            continue
        if v.vuln_id in config.ignore_rules:
            continue
        all_findings.append({
            "source": "sbom_osv",
            "severity": v.severity,
            "file": f"{v.package}=={v.version}",
            "line": 1,
            "rule_id": v.vuln_id,
            "cwe": "CWE-1395",
            "message": v.summary[:200] if v.summary else f"Vulnerability in {v.package}",
        })

    for s in secrets:
        if "CWE-798" in config.ignore_rules or s.rule_id in config.ignore_rules:
            continue
        all_findings.append({
            "source": "secrets",
            "severity": "CRITICAL",
            "file": s.file,
            "line": s.line,
            "rule_id": s.rule_id,
            "cwe": "CWE-798",
            "message": f"Hardcoded secret ({s.rule_id}): {s.match_preview}",
        })

    for sa in sast_findings:
        if not severity_meets_minimum(sa.severity, config.severity_minimum):
            continue
        if sa.rule_id in config.ignore_rules or sa.cwe in config.ignore_rules:
            continue
        all_findings.append({
            "source": "sast",
            "severity": sa.severity,
            "file": sa.file,
            "line": sa.line,
            "rule_id": sa.rule_id,
            "cwe": sa.cwe,
            "message": sa.message,
        })

    # 6. Format & output
    scan_output = ScanOutput(
        scan_id=scan_id,
        project_path=str(project_path.resolve()),
        risk_score=score_breakdown.total_score,
        score_breakdown=score_breakdown,
        components_count=len(components),
        findings=all_findings,
        started_at=started_at.isoformat(),
        finished_at=finished_at.isoformat(),
    )

    formatted = format_output(resolved_format, scan_output)

    if output and formatted:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(formatted, encoding="utf-8")
        if is_interactive:
            console.print(f"\n[dim]Results written to {output}[/]")
    elif formatted:
        # Non-table formats go to stdout (not stderr console)
        click.echo(formatted)

    # 7. Exit code based on threshold
    if score_breakdown.total_score > resolved_threshold:
        if is_interactive:
            console.print(
                f"\n[bold red]✗ POLICY VIOLATION:[/] Risk score {score_breakdown.total_score} "
                f"exceeds threshold {resolved_threshold}"
            )
        sys.exit(1)
    elif is_interactive:
        console.print(
            f"\n[bold green]✓ PASS:[/] Risk score {score_breakdown.total_score} "
            f"≤ threshold {resolved_threshold}"
        )


# --------------------------------------------------------------------------- #
# supplyguard report
# --------------------------------------------------------------------------- #


@main.command(name="report")
@click.argument("scan_id", type=int)
@click.option("--db-path", type=click.Path(path_type=Path), default="supplyguard.db")
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["table", "json", "sarif"], case_sensitive=False),
    default="table",
    help="Output format.",
)
def report_cmd(scan_id: int, db_path: Path, output_format: str) -> None:
    """Display detailed report of a previous scan from SQLite."""
    _, session_factory = init_db(db_path)
    with session_factory() as session:
        scan_rec = session.get(Scan, scan_id)
        if not scan_rec:
            console.print(f"[bold red]Scan ID {scan_id} not found in database.[/]")
            sys.exit(2)

        findings_list = []
        for f in scan_rec.findings:
            findings_list.append({
                "source": f.source,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "message": f.message,
            })

        scan_output = ScanOutput(
            scan_id=scan_rec.id,
            project_path=scan_rec.project_path,
            risk_score=scan_rec.risk_score,
            score_breakdown=calculate_risk_score([], [], []),  # Placeholder for stored scans
            components_count=scan_rec.components_count,
            findings=findings_list,
            started_at=str(scan_rec.started_at) if scan_rec.started_at else "",
            finished_at=str(scan_rec.finished_at) if scan_rec.finished_at else "",
        )

        formatted = format_output(output_format, scan_output)
        if formatted:
            click.echo(formatted)


# --------------------------------------------------------------------------- #
# supplyguard fix
# --------------------------------------------------------------------------- #


@main.command(name="fix")
@click.argument("project_path", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option("--dry-run", is_flag=True, help="Simulate fixes without modifying files.")
@click.option("--max-iterations", type=int, default=5, help="Maximum remediation loop cycles.")
@click.option("--no-llm", is_flag=True, help="Disable LLM-assisted patches.")
@click.option("--db-path", type=click.Path(path_type=Path), default="supplyguard.db")
def fix_cmd(
    project_path: Path, dry_run: bool, max_iterations: int, no_llm: bool, db_path: Path
) -> None:
    """Execute self-healing remediation loop on project_path."""
    from rich.table import Table as RichTable

    console.print(f"[bold green][FIX] Remediation:[/] {project_path.resolve()}")
    if dry_run:
        console.print("[yellow bold][!] DRY-RUN MODE: No files will be modified.[/]")

    _, session_factory = init_db(db_path)
    with session_factory() as session:
        scan_rec = Scan(
            project_path=str(project_path.resolve()),
            started_at=datetime.datetime.now(datetime.UTC),
            risk_score=0,
        )
        session.add(scan_rec)
        session.flush()

        report = remediate(
            project_path=project_path,
            max_iterations=max_iterations,
            dry_run=dry_run,
            use_llm=not no_llm,
            session=session,
            scan_id=scan_rec.id,
        )

        scan_rec.finished_at = datetime.datetime.now(datetime.UTC)
        scan_rec.risk_score = report.final_score
        session.commit()

    console.print()
    from rich.panel import Panel as RichPanel

    score_change = f"[red]{report.initial_score}[/] → [green]{report.final_score}[/]"
    console.print(
        RichPanel(
            f"Initial Risk: [bold]{report.initial_score}[/] | Final Risk: [bold]{report.final_score}[/] ({score_change})\n"
            f"Iterations: {report.iterations_run} | Resolved: [green]{report.resolved_count}[/] | "
            f"Failed: [red]{report.failed_count}[/] | Manual: [yellow]{report.manual_count}[/]",
            title="[bold][SUMMARY] Remediation Summary[/]",
        )
    )

    if report.manual_findings:
        m_table = RichTable(title="[!] Manual Human Action Required", header_style="bold yellow")
        m_table.add_column("Target", width=25)
        m_table.add_column("Rule / CWE", width=20)
        m_table.add_column("Specific Reason / Next Steps")
        for m in report.manual_findings:
            m_table.add_row(m["target"], m["rule"], m["reason"])
        console.print(m_table)


# --------------------------------------------------------------------------- #
# supplyguard web
# --------------------------------------------------------------------------- #


@main.command(name="web")
@click.option("--host", default="127.0.0.1", help="Dashboard bind address.")
@click.option("--port", default=5000, type=int, help="Dashboard port.")
@click.option("--db-path", type=click.Path(path_type=Path), default="supplyguard.db")
def web_cmd(host: str, port: int, db_path: Path) -> None:
    """Launch the SupplyGuard web dashboard."""
    from supplyguard.web.app import create_app

    app = create_app(db_path=db_path)
    console.print(f"[bold cyan][WEB] Dashboard:[/] http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
