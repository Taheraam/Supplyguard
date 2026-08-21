"""Flask route definitions for SupplyGuard dashboard views and API endpoints."""

from typing import Any

from flask import Blueprint, current_app, jsonify, render_template

from supplyguard.models import Finding, RemediationAttempt, Scan

web_bp = Blueprint("web", __name__)


@web_bp.route("/")
def index() -> str:
    """Dashboard homepage listing recent scans and platform summary metrics."""
    session_factory = current_app.config["SESSION_FACTORY"]
    with session_factory() as session:
        scans = (
            session.query(Scan)
            .order_by(Scan.started_at.desc())
            .limit(50)
            .all()
        )
        total_scans = len(scans)
        avg_score = (
            int(sum(s.risk_score for s in scans) / total_scans)
            if total_scans > 0
            else 0
        )
        total_findings = sum(s.findings_count for s in scans)

        return render_template(
            "dashboard.html",
            scans=scans,
            total_scans=total_scans,
            avg_score=avg_score,
            total_findings=total_findings,
        )


@web_bp.route("/scan/<int:scan_id>")
def scan_detail(scan_id: int) -> tuple[str, int] | str:
    """Detailed view of a specific scan session."""
    session_factory = current_app.config["SESSION_FACTORY"]
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return "Scan not found", 404

        findings = (
            session.query(Finding)
            .filter_by(scan_id=scan_id)
            .all()
        )
        has_remediations = (
            session.query(RemediationAttempt)
            .filter_by(scan_id=scan_id)
            .count()
            > 0
        )

        return render_template(
            "scan_detail.html",
            scan=scan,
            findings=findings,
            has_remediations=has_remediations,
        )


@web_bp.route("/scan/<int:scan_id>/remediation")
def remediation_view(scan_id: int) -> tuple[str, int] | str:
    """Remediation audit trail view with iteration timeline, diffs, and manual reasons."""
    session_factory = current_app.config["SESSION_FACTORY"]
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return "Scan not found", 404

        attempts = (
            session.query(RemediationAttempt)
            .filter_by(scan_id=scan_id)
            .order_by(RemediationAttempt.iteration.asc(), RemediationAttempt.id.asc())
            .all()
        )
        findings = (
            session.query(Finding)
            .filter_by(scan_id=scan_id)
            .all()
        )

        resolved_count = sum(1 for a in attempts if a.outcome in ("RESOLVED", "SIMULATED"))
        failed_count = sum(1 for a in attempts if a.outcome == "FIX_FAILED")

        # Group attempts by iteration for timeline
        iterations: dict[int, list[RemediationAttempt]] = {}
        for a in attempts:
            iterations.setdefault(a.iteration, []).append(a)

        return render_template(
            "remediation.html",
            scan=scan,
            attempts=attempts,
            iterations=iterations,
            findings=findings,
            resolved_count=resolved_count,
            failed_count=failed_count,
        )


@web_bp.route("/api/scans/<int:scan_id>")
def api_scan_data(scan_id: int) -> Any:
    """JSON API endpoint providing chart data and finding statistics."""
    session_factory = current_app.config["SESSION_FACTORY"]
    with session_factory() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404

        findings = (
            session.query(Finding)
            .filter_by(scan_id=scan_id)
            .all()
        )

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        source_counts = {"sbom_osv": 0, "secrets": 0, "sast": 0}

        for f in findings:
            sev = f.severity.upper()
            if "CRIT" in sev:
                sev_counts["CRITICAL"] += 1
            elif "HIGH" in sev or "ERROR" in sev:
                sev_counts["HIGH"] += 1
            elif "MED" in sev or "WARN" in sev:
                sev_counts["MEDIUM"] += 1
            else:
                sev_counts["LOW"] += 1

            src = f.source.lower()
            if src in source_counts:
                source_counts[src] += 1

        return jsonify(
            {
                "id": scan.id,
                "project_path": scan.project_path,
                "risk_score": scan.risk_score,
                "components_count": scan.components_count,
                "findings_count": scan.findings_count,
                "severity_breakdown": sev_counts,
                "source_breakdown": source_counts,
            }
        )
