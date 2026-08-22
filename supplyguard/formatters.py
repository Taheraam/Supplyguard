"""Output formatters for SupplyGuard scan results (table, JSON, SARIF v2.1.0)."""

import datetime
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from supplyguard.scoring.engine import ScoreBreakdown

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
TOOL_NAME = "SupplyGuard"
TOOL_VERSION = "0.3.0"
TOOL_URI = "https://github.com/supplyguard/supplyguard"


@dataclass
class ScanOutput:
    """Unified scan output container consumed by all formatters.

    Attributes:
        scan_id: Persisted scan ID from SQLite.
        project_path: Absolute path to the scanned project.
        risk_score: Computed weighted risk score (0-100).
        score_breakdown: Detailed category breakdown.
        components_count: Number of SBOM components discovered.
        findings: List of finding dicts with source, severity, file, line, rule_id, cwe, message.
        started_at: Scan start timestamp.
        finished_at: Scan end timestamp.
    """

    scan_id: int
    project_path: str
    risk_score: int
    score_breakdown: ScoreBreakdown
    components_count: int
    findings: list[dict[str, Any]]
    started_at: str = ""
    finished_at: str = ""


def format_output(fmt: str, scan_output: ScanOutput) -> str:
    """Dispatch to the appropriate formatter.

    Args:
        fmt: Output format name — "table", "json", or "sarif".
        scan_output: Unified scan data container.

    Returns:
        Formatted string output. For "table", prints to console and returns empty string.

    Raises:
        ValueError: If fmt is not a recognized format.
    """
    formatters = {
        "table": _format_table,
        "json": _format_json,
        "sarif": _format_sarif,
    }
    formatter = formatters.get(fmt)
    if not formatter:
        raise ValueError(f"Unknown format '{fmt}'. Choose from: {', '.join(formatters)}")
    return formatter(scan_output)


def _format_table(scan_output: ScanOutput) -> str:
    """Render Rich table output to console.

    Args:
        scan_output: Unified scan data.

    Returns:
        Empty string (output is printed directly to console).
    """
    console = Console(force_terminal=True)
    score = scan_output.risk_score
    color = "green" if score < 25 else "yellow" if score < 50 else "red"

    osv_count = sum(1 for f in scan_output.findings if f["source"] == "sbm_osv" or f["source"] == "sbom_osv")
    secrets_count = sum(1 for f in scan_output.findings if f["source"] == "secrets")
    sast_count = sum(1 for f in scan_output.findings if f["source"] == "sast")

    console.print()
    console.print(
        Panel(
            f"[bold {color}]Risk Score: {score}/100[/] | "
            f"Components: {scan_output.components_count} | OSV: {osv_count} | "
            f"Secrets: {secrets_count} | SAST: {sast_count}\n"
            f"[dim]Scan ID: {scan_output.scan_id} (persisted to SQLite)[/]",
            title="[bold][SHIELD] SupplyGuard Security Assessment[/]",
            expand=False,
        )
    )

    table = Table(title="Security Findings Summary", header_style="bold magenta")
    table.add_column("Source", style="cyan", width=10)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Location", width=30)
    table.add_column("Rule / CVE", width=22)
    table.add_column("Message")

    for f in scan_output.findings:
        sev = f["severity"]
        sev_style = "red" if sev in ("CRITICAL", "HIGH") else "yellow"
        source_label = {"sbom_osv": "OSV", "secrets": "Secrets", "sast": "SAST"}.get(f["source"], f["source"])

        location = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        rule = f.get("rule_id") or f.get("cwe", "")
        message = (f.get("message") or "")[:60]

        table.add_row(source_label, f"[{sev_style}]{sev}[/]", location, rule, message)

    console.print(table)
    return ""


def _format_json(scan_output: ScanOutput) -> str:
    """Render structured JSON output.

    Args:
        scan_output: Unified scan data.

    Returns:
        Pretty-printed JSON string.
    """
    output = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "scan_id": scan_output.scan_id,
        "project_path": scan_output.project_path,
        "risk_score": scan_output.risk_score,
        "score_breakdown": {
            "osv": scan_output.score_breakdown.osv_score,
            "secrets": scan_output.score_breakdown.secrets_score,
            "sast": scan_output.score_breakdown.sast_score,
            "findings_by_severity": scan_output.score_breakdown.findings_by_severity,
            "findings_by_source": scan_output.score_breakdown.findings_by_source,
        },
        "components_count": scan_output.components_count,
        "findings_count": len(scan_output.findings),
        "findings": scan_output.findings,
        "started_at": scan_output.started_at,
        "finished_at": scan_output.finished_at,
    }
    return json.dumps(output, indent=2, default=str)


# --------------------------------------------------------------------------- #
# SARIF v2.1.0 Formatter
# --------------------------------------------------------------------------- #

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_SEVERITY_TO_SARIF_RANK = {
    "CRITICAL": 95.0,
    "HIGH": 80.0,
    "MEDIUM": 50.0,
    "LOW": 20.0,
    "INFO": 10.0,
}


def _build_sarif_rule(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) from a finding.

    Args:
        finding: Single finding dict.

    Returns:
        SARIF rule dict.
    """
    rule_id = finding.get("rule_id") or finding.get("cwe", "unknown")
    cwe = finding.get("cwe", "")
    severity = finding.get("severity", "MEDIUM")

    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": finding.get("message", "Security finding")[:200]},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
        },
        "properties": {
            "security-severity": str(_SEVERITY_TO_SARIF_RANK.get(severity, 50.0)),
        },
    }

    if cwe and cwe.startswith("CWE-"):
        rule["relationships"] = [
            {
                "target": {
                    "id": cwe,
                    "toolComponent": {"name": "CWE"},
                },
                "kinds": ["superset"],
            }
        ]

    return rule


def _build_sarif_result(finding: dict[str, Any], idx: int) -> dict[str, Any]:
    """Build a SARIF result from a finding.

    Args:
        finding: Single finding dict.
        idx: Result index for correlation.

    Returns:
        SARIF result dict.
    """
    rule_id = finding.get("rule_id") or finding.get("cwe", "unknown")
    severity = finding.get("severity", "MEDIUM")
    line = finding.get("line", 1)

    return {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
        "message": {"text": finding.get("message", "Security finding")},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.get("file", "unknown"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(1, line),
                        "startColumn": 1,
                    },
                }
            }
        ],
        "properties": {
            "source": finding.get("source", "unknown"),
            "security-severity": str(_SEVERITY_TO_SARIF_RANK.get(severity, 50.0)),
        },
    }


def _format_sarif(scan_output: ScanOutput) -> str:
    """Render SARIF v2.1.0 compliant JSON output.

    This format is consumed by GitHub Code Scanning (upload-sarif action),
    VS Code SARIF Viewer, and other SARIF-compatible tools.

    Args:
        scan_output: Unified scan data.

    Returns:
        SARIF v2.1.0 JSON string.
    """
    # Deduplicate rules by rule_id
    seen_rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for idx, finding in enumerate(scan_output.findings):
        rule_id = finding.get("rule_id") or finding.get("cwe", "unknown")
        if rule_id not in seen_rules:
            seen_rules[rule_id] = _build_sarif_rule(finding)
        results.append(_build_sarif_result(finding, idx))

    sarif: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_output.started_at or datetime.datetime.now(datetime.UTC).isoformat(),
                        "endTimeUtc": scan_output.finished_at or datetime.datetime.now(datetime.UTC).isoformat(),
                    }
                ],
                "properties": {
                    "supplyguard:riskScore": scan_output.risk_score,
                    "supplyguard:scanId": scan_output.scan_id,
                    "supplyguard:componentsCount": scan_output.components_count,
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str)
