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


def is_test_file(file_path: str | None) -> bool:
    """Check if a file is an automated test suite file (e.g. tests/test_*.py).

    Args:
        file_path: Relative or absolute path string.

    Returns:
        True if file is in a dedicated tests/ test suite, False otherwise.
    """
    if not file_path:
        return False
    parts = [p.lower() for p in Path(file_path).parts]
    if "tests" in parts or "test" in parts:
        name = Path(file_path).name.lower()
        if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
            return True
    return False


def is_major_version_bump(current_version: str, fixed_version: str | None) -> bool:
    """Check if updating from current_version to fixed_version crosses a major version boundary.

    Args:
        current_version: Currently pinned version string.
        fixed_version: Proposed target version string.

    Returns:
        True if the upgrade is a major or breaking version bump (e.g. 0.x -> 1.x or 1.x -> 2.x), False otherwise.
    """
    if not current_version or not fixed_version:
        return False
    try:
        from packaging.version import InvalidVersion, Version

        curr = Version(current_version)
        fixed = Version(fixed_version)

        # Cross-major boundary: 0.x -> 1.x, 1.x -> 2.x, etc.
        if curr.major != fixed.major:
            return True

        return False
    except (InvalidVersion, TypeError, ValueError):
        return False


def classify(finding: Any) -> FixStrategy:
    """Classify a finding into its appropriate remediation strategy.

    Classification Mapping:
        - Test suite runner files (tests/test_*.py) -> MANUAL_REQUIRED
        - OSV Dependency with major version bump (e.g. 0.x -> 1.x) -> MANUAL_REQUIRED (breaking change)
        - OSV Dependency with compatible fixed_version (same major series) -> DETERMINISTIC
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
    # 0. Path-based check: Test suite runner files must never be auto-modified
    target_file = getattr(finding, "file", getattr(finding, "file_path", None))
    if target_file and is_test_file(str(target_file)):
        logger.info(f"Skipping auto-remediation for test suite file: {target_file}")
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
