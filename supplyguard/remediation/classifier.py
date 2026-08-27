"""Fixability classifier mapping findings to remediation strategies."""

import logging
from enum import Enum
from pathlib import Path
from typing import Any

from supplyguard.models import Finding
from supplyguard.sast.scanner import SastFinding
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import VulnMatch

logger = logging.getLogger(__name__)

NON_PRODUCTION_DIR_NAMES = {
    "examples",
    "example",
    "tests",
    "test",
    "fixtures",
    "fixture",
    "demos",
    "demo",
    "samples",
    "sample",
    "mocks",
    "mock",
}

COUPLED_ECOSYSTEM_PREFIXES = (
    "langchain",
    "langgraph",
    "langsmith",
)


class FixStrategy(str, Enum):
    """Remediation strategy classification for findings."""

    DETERMINISTIC = "DETERMINISTIC"
    LLM_ASSISTED = "LLM_ASSISTED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    HYBRID = "HYBRID"


def is_example_or_test_path(file_path: str | None) -> bool:
    """Check if a file path is within test, example, fixture, or demo directories.

    Args:
        file_path: Relative or absolute path string.

    Returns:
        True if file is in a non-production directory, False otherwise.
    """
    if not file_path:
        return False
    parts = Path(file_path).parts
    for part in parts:
        clean_part = part.lower().strip()
        if clean_part in NON_PRODUCTION_DIR_NAMES or any(
            clean_part.startswith(prefix) for prefix in ("test_", "demo_", "example_")
        ):
            return True
    return False


def is_major_version_bump(current_version: str, fixed_version: str | None) -> bool:
    """Check if updating from current_version to fixed_version crosses a major version boundary.

    Args:
        current_version: Currently pinned version string.
        fixed_version: Proposed target version string.

    Returns:
        True if the upgrade is a major or breaking version bump, False otherwise.
    """
    if not current_version or not fixed_version:
        return False
    try:
        from packaging.version import InvalidVersion, Version

        curr = Version(current_version)
        fixed = Version(fixed_version)

        # For >= 1.0 releases, major bump is curr.major != fixed.major
        if curr.major != fixed.major:
            return True

        # In 0.x (pre-1.0), minor version increments represent breaking changes
        if curr.major == 0 and fixed.major == 0 and curr.minor != fixed.minor:
            return True

        return False
    except (InvalidVersion, TypeError, ValueError):
        return False


def is_coupled_ecosystem(package_name: str) -> bool:
    """Check if a package is part of a tightly-coupled ecosystem requiring coordinated updates.

    Args:
        package_name: Name of the package to check.

    Returns:
        True if package belongs to a coupled ecosystem, False otherwise.
    """
    if not package_name:
        return False
    pkg = package_name.lower().strip()
    return any(
        pkg == p or pkg.startswith(f"{p}-") or pkg.startswith(f"{p}_")
        for p in COUPLED_ECOSYSTEM_PREFIXES
    )


def classify(finding: Any) -> FixStrategy:
    """Classify a finding into its appropriate remediation strategy.

    Classification Mapping:
        - Findings in example/test/fixture directories -> MANUAL_REQUIRED
        - OSV Dependency with major version bump -> MANUAL_REQUIRED (breaking change)
        - OSV Dependency in coupled ecosystem -> MANUAL_REQUIRED (requires coordinated update)
        - OSV Dependency with compatible fixed_version -> DETERMINISTIC
        - OSV Dependency without fixed_version -> MANUAL_REQUIRED
        - Hardcoded Secret (CWE-798) in production code -> HYBRID
        - CWE-295 (verify=False) -> DETERMINISTIC
        - CWE-489 (debug=True) -> DETERMINISTIC
        - CWE-347 (JWT verify disabled) -> DETERMINISTIC
        - CWE-330 (random for tokens) -> DETERMINISTIC
        - CWE-89 (SQL string concatenation) -> LLM_ASSISTED
        - CWE-78 (subprocess shell=True) -> LLM_ASSISTED
        - CWE-916 (Weak MD5/SHA1 hash) -> LLM_ASSISTED
        - CWE-862 (Missing auth on sensitive route) -> MANUAL_REQUIRED
        - CWE-94 / CWE-502 (eval/exec/pickle on variable) -> MANUAL_REQUIRED
        - CWE-942 (CORS wildcard + credentials) -> MANUAL_REQUIRED

    Args:
        finding: Finding object (Finding model, VulnMatch, SecretFinding, or SastFinding).

    Returns:
        FixStrategy enum member.
    """
    # 0. Path-based check: Test, example, fixture, and demo files must never be auto-modified
    target_file = getattr(finding, "file", getattr(finding, "file_path", None))
    if target_file and is_example_or_test_path(str(target_file)):
        logger.info(f"Skipping auto-remediation for test/example file: {target_file}")
        return FixStrategy.MANUAL_REQUIRED

    # 1. OSV Vulnerabilities
    if isinstance(finding, VulnMatch):
        if not finding.fixed_version:
            return FixStrategy.MANUAL_REQUIRED

        if is_major_version_bump(finding.version, finding.fixed_version):
            logger.warning(
                f"Breaking change warning: {finding.package} upgrade "
                f"({finding.version} -> {finding.fixed_version}) crosses a major version boundary. "
                "Classified as MANUAL_REQUIRED."
            )
            return FixStrategy.MANUAL_REQUIRED

        if is_coupled_ecosystem(finding.package):
            logger.warning(
                f"Coupled ecosystem warning: {finding.package} belongs to a coupled ecosystem. "
                "Classified as MANUAL_REQUIRED."
            )
            return FixStrategy.MANUAL_REQUIRED

        return FixStrategy.DETERMINISTIC

    # 2. Secrets
    if isinstance(finding, SecretFinding):
        return FixStrategy.HYBRID

    # 3. SAST Finding
    if isinstance(finding, SastFinding):
        rule_id = finding.rule_id
        cwe = finding.cwe.upper()

        if "requests-verify-false" in rule_id or "CWE-295" in cwe:
            return FixStrategy.DETERMINISTIC
        if "flask-debug-true" in rule_id or "CWE-489" in cwe:
            return FixStrategy.DETERMINISTIC
        if "jwt-unverified-decode" in rule_id or "CWE-347" in cwe:
            return FixStrategy.DETERMINISTIC
        if "insecure-random-token" in rule_id or "CWE-330" in cwe:
            return FixStrategy.DETERMINISTIC

        if "sql-injection" in rule_id or "CWE-89" in cwe:
            return FixStrategy.LLM_ASSISTED
        if "subprocess-shell-true" in rule_id or "CWE-78" in cwe:
            return FixStrategy.LLM_ASSISTED
        if "weak-hash" in rule_id or "CWE-916" in cwe:
            return FixStrategy.LLM_ASSISTED

        # Everything else is manual-required
        return FixStrategy.MANUAL_REQUIRED

    # 4. Database Model Finding
    if isinstance(finding, Finding):
        source = finding.source.lower()
        if source == "sbom_osv":
            if "breaking" in finding.message.lower() or "major" in finding.message.lower():
                return FixStrategy.MANUAL_REQUIRED
            if "fixed" in finding.message.lower():
                return FixStrategy.DETERMINISTIC
            return FixStrategy.MANUAL_REQUIRED
        if source == "secrets":
            return FixStrategy.HYBRID

        rule_id = finding.rule_id
        cwe = finding.cwe.upper()
        if any(
            r in rule_id for r in ("verify-false", "debug-true", "jwt-unverified", "random-token")
        ) or any(c in cwe for c in ("CWE-295", "CWE-489", "CWE-347", "CWE-330")):
            return FixStrategy.DETERMINISTIC
        if any(r in rule_id for r in ("sql-injection", "subprocess", "weak-hash")) or any(
            c in cwe for c in ("CWE-89", "CWE-78", "CWE-916")
        ):
            return FixStrategy.LLM_ASSISTED
        return FixStrategy.MANUAL_REQUIRED

    return FixStrategy.MANUAL_REQUIRED
