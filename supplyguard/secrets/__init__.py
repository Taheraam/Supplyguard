"""Secrets detection module with zero-leakage redaction."""

from supplyguard.secrets.scanner import SecretFinding, scan_secrets

__all__ = ["SecretFinding", "scan_secrets"]
