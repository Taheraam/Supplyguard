"""Remediation loop orchestrating scan, classification, fix attempts, and verification."""

import concurrent.futures
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from supplyguard.models import RemediationAttempt
from supplyguard.remediation.classifier import (
    FixStrategy,
    classify,
    is_major_version_bump,
    is_test_file,
)
from supplyguard.remediation.deterministic_fixer import (
    fix_dependency,
    fix_sast_deterministic,
    fix_secret_hybrid,
)
from supplyguard.remediation.llm_fixer import (
    AnthropicPatchProvider,
    PatchProvider,
    fix_llm_assisted,
)
from supplyguard.remediation.verifier import FixOutcome
from supplyguard.sast.scanner import SastFinding, run_sast
from supplyguard.sbom.generator import Component, generate_sbom
from supplyguard.scoring.engine import ScoreBreakdown, calculate_risk_score
from supplyguard.secrets.scanner import SecretFinding, scan_secrets
from supplyguard.vulns.osv_client import VulnMatch, batch_query

logger = logging.getLogger(__name__)


@dataclass
class RemediationAttemptRecord:
    """Audit record of a single remediation attempt."""

    finding_type: str
    target: str
    strategy: str
    outcome: str
    diff: str = ""
    explanation: str = ""
    reason: str = ""


@dataclass
class RemediationReport:
    """Summary report of the remediation run."""

    initial_score: int
    final_score: int
    iterations_run: int
    resolved_count: int
    failed_count: int
    manual_count: int
    attempts: list[RemediationAttemptRecord] = field(default_factory=list)
    manual_findings: list[dict[str, str]] = field(default_factory=list)
    history: list[dict[str, int]] = field(default_factory=list)


def _scan_all(
    project_path: Path,
) -> tuple[list[Component], list[VulnMatch], list[SecretFinding], list[SastFinding], ScoreBreakdown]:
    """Execute complete scanner pipeline over project_path."""
    # 1. SBOM + OSV
    _, components = generate_sbom(project_path)
    vulns = batch_query(components)

    # 2. Parallel Secrets + SAST
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_secrets = executor.submit(scan_secrets, project_path)
        future_sast = executor.submit(run_sast, project_path)
        secrets = future_secrets.result()
        sast_findings = future_sast.result()

    score = calculate_risk_score(vulns, secrets, sast_findings)
    return components, vulns, secrets, sast_findings, score


def _get_manual_reason(finding: Any) -> str:
    """Generate clear, actionable reason why a finding is manual-required."""
    target_file = getattr(finding, "file", getattr(finding, "file_path", None))
    if target_file and is_test_file(str(target_file)):
        return (
            f"File '{target_file}' is in an automated test suite; "
            "automated modifications to test files are disabled."
        )

    if isinstance(finding, VulnMatch):
        if not finding.fixed_version:
            return f"Vulnerability in {finding.package} has no published fix_version yet."
        if is_major_version_bump(finding.version, finding.fixed_version):
            return (
                f"Upgrading {finding.package} from {finding.version} to {finding.fixed_version} "
                "crosses a major version boundary (potential breaking change). Manual architectural review required."
            )
        return f"Dependency {finding.package} requires manual review."

    if isinstance(finding, SastFinding):
        if "admin" in finding.rule_id or "CWE-862" in finding.cwe:
            return "Missing authorization logic requires developer architecture decision for intended auth scheme."
        if "eval" in finding.rule_id or "CWE-94" in finding.cwe or "CWE-502" in finding.cwe:
            return "Dynamic code execution or pickle deserialization is context-dependent and requires architectural refactoring."
        if "cors" in finding.rule_id or "CWE-942" in finding.cwe:
            return "CORS configuration requires explicit whitelist of authorized domain origins."

    return "Requires manual human security review."


def remediate(
    project_path: Path,
    max_iterations: int = 5,
    dry_run: bool = False,
    use_llm: bool = True,
    patch_provider: PatchProvider | None = None,
    session = None,
    scan_id: int | None = None,
) -> RemediationReport:
    """Execute the full self-healing remediation loop on project_path.

    Args:
        project_path: Target directory to remediate.
        max_iterations: Maximum number of fix-and-rescan iterations.
        dry_run: If True, only simulate fixes without modifying files.
        use_llm: Whether to attempt LLM-assisted patches.
        patch_provider: Optional custom PatchProvider.
        session: Optional SQLAlchemy session for persistence.
        scan_id: Optional existing scan ID to link attempts to.

    Returns:
        RemediationReport with full audit trail and before/after metrics.
    """
    logger.info(f"Starting remediation loop for {project_path} (dry_run={dry_run})")
    history: list[dict[str, int]] = []
    all_attempts: list[RemediationAttemptRecord] = []
    provider = patch_provider or AnthropicPatchProvider()

    # Initial baseline scan
    _, _, _, _, initial_score = _scan_all(project_path)

    for iteration in range(1, max_iterations + 1):
        _, cur_vulns, cur_secrets, cur_sast, _ = _scan_all(project_path)
        all_findings: list[Any] = [*cur_vulns, *cur_secrets, *cur_sast]

        auto_fixable = [f for f in all_findings if classify(f) != FixStrategy.MANUAL_REQUIRED]
        if not auto_fixable:
            logger.info(f"Iteration {iteration}: No auto-fixable findings remain.")
            break

        resolved_this_round = 0

        for finding in auto_fixable:
            strategy = classify(finding)
            target = getattr(finding, "file", getattr(finding, "package", "unknown"))

            if dry_run:
                all_attempts.append(
                    RemediationAttemptRecord(
                        finding_type=type(finding).__name__,
                        target=str(target),
                        strategy=strategy.value,
                        outcome="SIMULATED",
                        explanation="[Dry Run] Would attempt fix.",
                    )
                )
                resolved_this_round += 1
                continue

            outcome = FixOutcome.FIX_FAILED
            diff = ""
            explanation = ""

            if strategy == FixStrategy.DETERMINISTIC:
                if isinstance(finding, VulnMatch) and finding.fixed_version:
                    outcome, diff = fix_dependency(project_path, finding.package, finding.fixed_version)
                    explanation = f"Bumped {finding.package} to {finding.fixed_version} in requirements.txt."
                elif isinstance(finding, SastFinding):
                    outcome, diff = fix_sast_deterministic(project_path, finding)
                    explanation = f"Applied deterministic rewrite for rule {finding.rule_id}."

            elif strategy == FixStrategy.HYBRID and isinstance(finding, SecretFinding):
                outcome, diff, notice = fix_secret_hybrid(project_path, finding)
                explanation = notice

            elif strategy == FixStrategy.LLM_ASSISTED and isinstance(finding, SastFinding):
                if use_llm:
                    outcome, diff, explanation = fix_llm_assisted(project_path, finding, provider)
                else:
                    outcome = FixOutcome.SKIPPED
                    explanation = "LLM fixes disabled via --no-llm flag."

            if outcome == FixOutcome.RESOLVED:
                resolved_this_round += 1

            attempt_rec = RemediationAttemptRecord(
                finding_type=type(finding).__name__,
                target=str(target),
                strategy=strategy.value,
                outcome=outcome.value,
                diff=diff,
                explanation=explanation,
            )
            all_attempts.append(attempt_rec)

            # Persist to database if session provided
            if session and scan_id:
                db_attempt = RemediationAttempt(
                    scan_id=scan_id,
                    strategy=strategy.value,
                    iteration=iteration,
                    outcome=outcome.value,
                    diff_text=diff,
                    explanation=explanation,
                )
                session.add(db_attempt)
                session.commit()

        history.append({"iteration": iteration, "resolved": resolved_this_round})
        logger.info(f"Iteration {iteration}: Resolved {resolved_this_round} findings.")

        if dry_run or resolved_this_round == 0:
            logger.info("Stopping remediation loop: dry_run complete or zero progress made in this round.")
            break

    # Final post-remediation scan
    _, final_vulns, final_secrets, final_sast, final_score = _scan_all(project_path)

    manual_list: list[dict[str, str]] = []
    for f in [*final_vulns, *final_secrets, *final_sast]:
        if classify(f) == FixStrategy.MANUAL_REQUIRED:
            manual_list.append(
                {
                    "target": getattr(f, "file", getattr(f, "package", "")),
                    "rule": getattr(f, "rule_id", getattr(f, "vuln_id", "Manual")),
                    "reason": _get_manual_reason(f),
                }
            )

    resolved_total = sum(1 for a in all_attempts if a.outcome in ("RESOLVED", "SIMULATED"))
    failed_total = sum(1 for a in all_attempts if a.outcome == "FIX_FAILED")

    return RemediationReport(
        initial_score=initial_score.total_score,
        final_score=final_score.total_score if not dry_run else initial_score.total_score,
        iterations_run=len(history),
        resolved_count=resolved_total,
        failed_count=failed_total,
        manual_count=len(manual_list),
        attempts=all_attempts,
        manual_findings=manual_list,
        history=history,
    )
