"""Deterministic fix implementations for dependencies and Semgrep autofixes."""

import logging
import re
from pathlib import Path

from supplyguard.remediation.verifier import FixOutcome, apply_with_verification
from supplyguard.sast.scanner import SastFinding, run_sast
from supplyguard.secrets.scanner import SecretFinding

logger = logging.getLogger(__name__)


def fix_dependency(
    project_path: Path, package_name: str, fixed_version: str
) -> tuple[FixOutcome, str]:
    """Bump vulnerable dependency version in requirements.txt to fixed_version.

    Args:
        project_path: Project root path containing requirements.txt.
        package_name: Name of the package to update.
        fixed_version: Target non-vulnerable version.

    Returns:
        Tuple of (FixOutcome, diff_text).
    """
    req_path = project_path / "requirements.txt"
    if not req_path.exists():
        return FixOutcome.FIX_FAILED, ""

    def _patch() -> None:
        lines = req_path.read_text(encoding="utf-8").splitlines()
        new_lines: list[str] = []
        pattern = re.compile(rf"^{re.escape(package_name)}(?:[<>=~!].*)?$", re.IGNORECASE)
        for line in lines:
            if pattern.match(line.strip()):
                new_lines.append(f"{package_name}=={fixed_version}")
            else:
                new_lines.append(line)
        req_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    def _check() -> bool:
        content = req_path.read_text(encoding="utf-8")
        return f"{package_name}=={fixed_version}" in content

    return apply_with_verification(req_path, _patch, _check, project_path)


def fix_sast_deterministic(
    project_path: Path, finding: SastFinding
) -> tuple[FixOutcome, str]:
    """Apply deterministic code rewrite for supported SAST rules.

    Supported Rules:
        - ai-requests-verify-false (CWE-295) -> remove verify=False
        - ai-flask-debug-true (CWE-489) -> set debug=False
        - ai-jwt-unverified-decode (CWE-347) -> set verify=True
        - ai-insecure-random-token (CWE-330) -> swap random to secrets

    Args:
        project_path: Root path of the scanned project.
        finding: SastFinding instance to resolve.

    Returns:
        Tuple of (FixOutcome, diff_text).
    """
    target_file = project_path / finding.file
    if not target_file.exists():
        return FixOutcome.FIX_FAILED, ""

    initial_matching = [
        f for f in run_sast(project_path)
        if f.file == finding.file and f.rule_id == finding.rule_id
    ]
    initial_count = len(initial_matching)

    def _patch() -> None:
        content = target_file.read_text(encoding="utf-8")
        rule = finding.rule_id

        if "requests-verify-false" in rule or "CWE-295" in finding.cwe:
            # Replace verify=False with verify=True or remove it
            patched = re.sub(r",\s*verify\s*=\s*False", "", content)
            if patched == content:
                patched = re.sub(r"verify\s*=\s*False", "verify=True", content)
            target_file.write_text(patched, encoding="utf-8")

        elif "flask-debug-true" in rule or "CWE-489" in finding.cwe:
            patched = re.sub(r"\bdebug\s*=\s*True\b", "debug=False", content)
            target_file.write_text(patched, encoding="utf-8")

        elif "jwt-unverified-decode" in rule or "CWE-347" in finding.cwe:
            patched = re.sub(r"\bverify\s*=\s*False\b", "verify=True", content)
            patched = re.sub(r'options\s*=\s*\{["\']verify_signature["\']\s*:\s*False\}', 'options={"verify_signature": True}', patched)
            target_file.write_text(patched, encoding="utf-8")

        elif "insecure-random-token" in rule or "CWE-330" in finding.cwe:
            # Ensure secrets import and swap call
            patched = content
            if "import secrets" not in patched:
                patched = "import secrets\n" + patched
            patched = re.sub(r"\brandom\.choice\(", "secrets.choice(", patched)

            def _replace_randint(m: re.Match) -> str:
                a, b = m.group(1).strip(), m.group(2).strip()
                return f"({a} + secrets.randbelow({b} - {a} + 1))"

            patched = re.sub(r"\brandom\.randint\(([^,]+),([^)]+)\)", _replace_randint, patched)
            target_file.write_text(patched, encoding="utf-8")

    def _check() -> bool:
        # Re-run SAST check on file and verify finding count decreased
        findings = run_sast(project_path)
        matching = [
            f for f in findings
            if f.file == finding.file and f.rule_id == finding.rule_id
        ]
        return len(matching) < initial_count or len(matching) == 0

    return apply_with_verification(target_file, _patch, _check, project_path)


def fix_secret_hybrid(
    project_path: Path, finding: SecretFinding
) -> tuple[FixOutcome, str, str]:
    """Document exposed secret in .env.example (name only) and issue rotation notice.

    Args:
        project_path: Project root path.
        finding: SecretFinding instance.

    Returns:
        Tuple of (FixOutcome, diff_text, rotation_notice).
    """
    env_example = project_path / ".env.example"
    var_name = f"SECRET_{finding.rule_id.upper().replace('-', '_')}"

    def _patch() -> None:
        existing = env_example.read_text(encoding="utf-8") if env_example.exists() else ""
        if var_name not in existing:
            new_content = existing + (f"\n{var_name}=\n" if existing else f"{var_name}=\n")
            env_example.write_text(new_content, encoding="utf-8")

    def _check() -> bool:
        return env_example.exists() and var_name in env_example.read_text(encoding="utf-8")

    outcome, diff = apply_with_verification(env_example, _patch, _check, project_path)
    notice = (
        f"CRITICAL: Secret detected at {finding.file}:{finding.line}. "
        f"Created env var stub '{var_name}' in .env.example. "
        "Rotate the leaked credential immediately in your identity/cloud provider."
    )
    return outcome, diff, notice
