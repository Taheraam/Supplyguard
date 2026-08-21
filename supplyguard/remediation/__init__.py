"""Remediation and self-healing engine for SupplyGuard."""

from supplyguard.remediation.classifier import FixStrategy, classify
from supplyguard.remediation.deterministic_fixer import (
    fix_dependency,
    fix_sast_deterministic,
)
from supplyguard.remediation.llm_fixer import (
    AnthropicPatchProvider,
    PatchProvider,
    fix_llm_assisted,
)
from supplyguard.remediation.loop import RemediationReport, remediate
from supplyguard.remediation.verifier import FixOutcome, apply_with_verification

__all__ = [
    "AnthropicPatchProvider",
    "FixOutcome",
    "FixStrategy",
    "PatchProvider",
    "RemediationReport",
    "apply_with_verification",
    "classify",
    "fix_dependency",
    "fix_llm_assisted",
    "fix_sast_deterministic",
    "remediate",
]
