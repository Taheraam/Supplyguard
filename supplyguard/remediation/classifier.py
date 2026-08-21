"""Fixability classifier mapping findings to remediation strategies."""

from enum import Enum
from typing import Any

from supplyguard.models import Finding
from supplyguard.sast.scanner import SastFinding
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import VulnMatch


class FixStrategy(str, Enum):
    """Remediation strategy classification for findings."""

    DETERMINISTIC = "DETERMINISTIC"
    LLM_ASSISTED = "LLM_ASSISTED"
    MANUAL_REQUIRED = "MANUAL_REQUIRED"
    HYBRID = "HYBRID"


def classify(finding: Any) -> FixStrategy:
    """Classify a finding into its appropriate remediation strategy.

    Classification Mapping:
        - OSV Dependency with known fixed_version -> DETERMINISTIC
        - OSV Dependency without fixed_version -> MANUAL_REQUIRED
        - Hardcoded Secret (CWE-798) -> HYBRID
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
    # 1. OSV Vulnerabilities
    if isinstance(finding, VulnMatch):
        return (
            FixStrategy.DETERMINISTIC
            if finding.fixed_version
            else FixStrategy.MANUAL_REQUIRED
        )

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
            # Check if fixed_version exists in raw_json or message
            if "fixed" in finding.message.lower():
                return FixStrategy.DETERMINISTIC
            return FixStrategy.MANUAL_REQUIRED
        if source == "secrets":
            return FixStrategy.HYBRID

        rule_id = finding.rule_id
        cwe = finding.cwe.upper()
        if any(r in rule_id for r in ("verify-false", "debug-true", "jwt-unverified", "random-token")) or any(
            c in cwe for c in ("CWE-295", "CWE-489", "CWE-347", "CWE-330")
        ):
            return FixStrategy.DETERMINISTIC
        if any(r in rule_id for r in ("sql-injection", "subprocess", "weak-hash")) or any(
            c in cwe for c in ("CWE-89", "CWE-78", "CWE-916")
        ):
            return FixStrategy.LLM_ASSISTED
        return FixStrategy.MANUAL_REQUIRED

    return FixStrategy.MANUAL_REQUIRED
