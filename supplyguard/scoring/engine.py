"""Risk scoring engine computing transparent, auditable 0-100 risk scores."""

from dataclasses import dataclass, field

from supplyguard.sast.scanner import SastFinding
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import VulnMatch


@dataclass
class ScoreBreakdown:
    """Detailed category breakdown of the risk score."""

    total_score: int
    osv_score: int
    secrets_score: int
    sast_score: int
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_source: dict[str, int] = field(default_factory=dict)


def calculate_risk_score(
    vulns: list[VulnMatch],
    secrets: list[SecretFinding],
    sast_findings: list[SastFinding],
) -> ScoreBreakdown:
    """Calculate an auditable, weighted security risk score from 0 to 100.

    Weighted Scoring Formula:
        - OSV Vulnerabilities:
            - +10 points per CRITICAL severity
            - +5 points per HIGH severity
            - +2 points per MEDIUM or LOW severity
        - Secrets Scanner:
            - +15 points per Secret finding (heaviest weight — immediately exploitable)
        - SAST / AI-Code-Smell Findings:
            - +8 points per HIGH severity finding
            - +3 points per MEDIUM severity finding
            - +1 point per LOW or INFO severity finding
        - Total is capped at 100.

    Args:
        vulns: List of OSV vulnerability matches.
        secrets: List of detected secrets.
        sast_findings: List of SAST findings.

    Returns:
        ScoreBreakdown dataclass with total score and categorized points.
    """
    osv_score = 0
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    source_counts = {"sbom_osv": len(vulns), "secrets": len(secrets), "sast": len(sast_findings)}

    for vuln in vulns:
        sev = vuln.severity.upper()
        if "CRIT" in sev:
            osv_score += 10
            sev_counts["CRITICAL"] += 1
        elif "HIGH" in sev:
            osv_score += 5
            sev_counts["HIGH"] += 1
        else:
            osv_score += 2
            sev_counts["MEDIUM" if "MED" in sev else "LOW"] += 1

    # Secrets have heaviest weight (15 pts each) and are critical
    secrets_score = len(secrets) * 15
    sev_counts["CRITICAL"] += len(secrets)

    sast_score = 0
    for sast in sast_findings:
        sev = sast.severity.upper()
        if "CRIT" in sev:
            sast_score += 10
            sev_counts["CRITICAL"] += 1
        elif "HIGH" in sev or "ERROR" in sev:
            sast_score += 8
            sev_counts["HIGH"] += 1
        elif "MED" in sev or "WARN" in sev:
            sast_score += 3
            sev_counts["MEDIUM"] += 1
        else:
            sast_score += 1
            sev_counts["LOW"] += 1

    raw_total = osv_score + secrets_score + sast_score
    total_score = min(100, raw_total)

    return ScoreBreakdown(
        total_score=total_score,
        osv_score=osv_score,
        secrets_score=secrets_score,
        sast_score=sast_score,
        findings_by_severity=sev_counts,
        findings_by_source=source_counts,
    )
