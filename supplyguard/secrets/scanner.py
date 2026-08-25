"""Secrets detection scanner wrapping Gitleaks with strict zero-leakage redaction."""

import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SecretFinding:
    """Represents a detected hardcoded secret with redacted match preview."""

    file: str
    line: int
    rule_id: str
    match_preview: str
    description: str = ""


class GitleaksNotFoundError(Exception):
    """Raised when the gitleaks executable is not found on PATH."""


def _path_matches_ignore(rel_path: str, ignore_patterns: list[str]) -> bool:
    """Check if a relative path matches any of the ignore patterns.

    Supports directory patterns (ending with '/') and exact file name matches.

    Args:
        rel_path: Relative file path to check.
        ignore_patterns: List of patterns from .supplyguard.yml ignore_paths.

    Returns:
        True if the path should be ignored.
    """
    normalized = rel_path.replace("\\", "/")
    for pattern in ignore_patterns:
        clean = pattern.strip().rstrip("/")
        # Directory prefix match (e.g., "examples/" matches "examples/foo.py")
        if normalized.startswith(clean + "/") or normalized == clean:
            return True
        # Basename match (e.g., "implementation_plan_v1" matches the file directly)
        if "/" not in clean and clean in normalized.split("/"):
            return True
    return False


def redact_secret(raw_secret: str) -> str:
    """Redact secret string keeping only first 3 and last 3 characters.

    Never exposes full secret tokens in logs, models, or UI.

    Args:
        raw_secret: Raw discovered secret value.

    Returns:
        Redacted string preview (e.g. 'AKIA...XYZ').
    """
    clean = raw_secret.strip().strip("'\"")
    if len(clean) <= 6:
        return "***"
    return f"{clean[:3]}...{clean[-3:]}"


def _run_gitleaks_cli(project_path: Path) -> list[SecretFinding]:
    """Execute gitleaks CLI against project_path and parse JSON results.

    Args:
        project_path: Directory path to scan.

    Returns:
        List of SecretFinding instances.

    Raises:
        GitleaksNotFoundError: If gitleaks is not on PATH.
    """
    gitleaks_bin = shutil.which("gitleaks")
    if not gitleaks_bin:
        raise GitleaksNotFoundError(
            "Gitleaks is not installed or not found on PATH. "
            "Please install Gitleaks: https://github.com/gitleaks/gitleaks/releases"
        )

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
        report_path = Path(tmp_file.name)

    try:
        cmd = [
            gitleaks_bin,
            "detect",
            "--source",
            str(project_path),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-git",
        ]
        # gitleaks returns exit code 1 when leaks are found
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )

        findings: list[SecretFinding] = []
        if report_path.exists() and report_path.stat().st_size > 0:
            content = report_path.read_text(encoding="utf-8")
            data = json.loads(content)
            for item in data:
                raw_match = item.get("Secret", "") or item.get("Match", "")
                findings.append(
                    SecretFinding(
                        file=item.get("File", ""),
                        line=int(item.get("StartLine", 1)),
                        rule_id=item.get("RuleID", "generic-secret"),
                        match_preview=redact_secret(raw_match),
                        description=item.get("Description", "Potential hardcoded secret"),
                    )
                )
        return findings
    finally:
        if report_path.exists():
            report_path.unlink()


def _fallback_regex_scan(project_path: Path, ignore_paths: list[str] | None = None) -> list[SecretFinding]:
    """Built-in regex fallback secrets scanner if gitleaks CLI is unavailable.

    Args:
        project_path: Directory path to scan.
        ignore_paths: List of path patterns to exclude from scanning.

    Returns:
        List of SecretFinding instances.
    """
    import os

    patterns = [
        ("generic-api-key", re.compile(r"""(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{8,})['"]""", re.IGNORECASE)),
        ("aws-access-key", re.compile(r"""(AKIA[0-9A-Z]{16})""")),
        ("jwt-token", re.compile(r"""(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)""")),
        ("fake-test-key", re.compile(r"""(FAKE_KEY_FOR_TESTING_DO_NOT_USE|TEST_API_KEY_[A-Z0-9_]+)""")),
    ]

    excluded = ignore_paths or []
    findings: list[SecretFinding] = []
    ignore_dirs = {".git", ".venv", "node_modules", "__pycache__", ".agent", ".pytest_cache"}

    for root, dirs, files in os.walk(str(project_path)):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            file_path = Path(root) / f
            rel_str = str(file_path.relative_to(project_path))

            # Skip files matching any ignore_paths pattern
            if _path_matches_ignore(rel_str, excluded):
                continue

            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line_no, line_content in enumerate(lines, start=1):
                for rule_id, pattern in patterns:
                    match = pattern.search(line_content)
                    if match:
                        raw_secret = match.group(1) if match.groups() else match.group(0)
                        findings.append(
                            SecretFinding(
                                file=rel_str,
                                line=line_no,
                                rule_id=rule_id,
                                match_preview=redact_secret(raw_secret),
                                description=f"Identified {rule_id}",
                            )
                        )
    return findings


def scan_secrets(
    project_path: Path,
    allow_fallback: bool = True,
    ignore_paths: list[str] | None = None,
) -> list[SecretFinding]:
    """Scan project for hardcoded secrets and credentials.

    Args:
        project_path: Directory path of the target codebase.
        allow_fallback: Whether to use regex fallback if gitleaks is absent.
        ignore_paths: Path patterns to exclude from scanning.

    Returns:
        List of SecretFinding with redacted previews.
    """
    try:
        findings = _run_gitleaks_cli(project_path)
    except GitleaksNotFoundError as err:
        if allow_fallback:
            logger.debug(f"{err}. Falling back to internal regex scanner.")
            return _fallback_regex_scan(project_path, ignore_paths=ignore_paths)
        raise

    # Filter gitleaks results by ignore_paths too
    if ignore_paths:
        findings = [
            f for f in findings
            if not _path_matches_ignore(f.file, ignore_paths)
        ]
    return findings
