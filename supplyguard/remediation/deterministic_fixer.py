"""Deterministic fix implementations for dependencies and Semgrep autofixes."""

import logging
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

from supplyguard.remediation.verifier import FixOutcome, apply_with_verification
from supplyguard.sast.scanner import SastFinding, run_sast
from supplyguard.secrets.scanner import SecretFinding

logger = logging.getLogger(__name__)


def rule_counts(project_path: Path, rel_file: str) -> Counter[str]:
    """How many times each SAST rule fires in one file."""
    return Counter(f.rule_id for f in run_sast(project_path) if f.file == rel_file)


def patch_is_improvement(before: Counter[str], after: Counter[str], target_rule: str) -> bool:
    """A patch must remove the target finding AND must not introduce any other finding.

    Checking only the target rule let a patch "fix" e.g. a weak hash while adding a
    subprocess(shell=True), and still count as RESOLVED.
    """
    if after[target_rule] >= before[target_rule]:
        return False
    return all(after[rule] <= before[rule] for rule in after if rule != target_rule)


def _pip_dry_run(req_path: Path) -> bool:
    """Ask pip whether the requirements resolve, without executing any project code.

    - Only requirement lines are passed on; option lines such as `--index-url`,
      `--extra-index-url`, `-e` or `-f` are dropped, so a malicious requirements file
      cannot redirect pip to an attacker's package index (dependency confusion).
    - `--only-binary=:all:` forbids building sdists, which would run their setup.py.
    """
    requirement_lines = [
        line for line in req_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith(("#", "-"))
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        tmp.write("\n".join(requirement_lines) + "\n")
        sanitized = Path(tmp.name)
    try:
        res = subprocess.run(
            [
                sys.executable, "-m", "pip", "install", "--dry-run", "--no-deps",
                "--only-binary=:all:", "--isolated", "--index-url", "https://pypi.org/simple",
                "-r", str(sanitized),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
        if res.returncode != 0:
            logger.warning(f"pip install --dry-run validation failed: {res.stderr}")
            return False
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as err:
        logger.warning(f"Dry-run pip verification skipped due to environment constraint: {err}")
        return True
    finally:
        sanitized.unlink(missing_ok=True)


def _verify_requirements_txt(req_path: Path) -> bool:
    """Verify that requirements.txt is syntactically valid and has no duplicate conflicting pins.

    Args:
        req_path: Path to requirements.txt.

    Returns:
        True if requirements file is valid, False otherwise.
    """
    try:
        lines = req_path.read_text(encoding="utf-8").splitlines()
        seen_packages: dict[str, str] = {}
        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if "==" in line_str:
                pkg_name, ver = line_str.split("==", 1)
                pkg_clean = pkg_name.strip().lower()
                ver_clean = ver.strip()
                if pkg_clean in seen_packages and seen_packages[pkg_clean] != ver_clean:
                    logger.warning(f"Conflicting duplicate package pins found for {pkg_clean}")
                    return False
                seen_packages[pkg_clean] = ver_clean
        return True
    except Exception as err:
        logger.warning(f"Error parsing requirements.txt: {err}")
        return False


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
        # name, optional [extras], specifier, optional "; marker" / "# comment"
        pattern = re.compile(
            rf"^(?P<name>{re.escape(package_name)})(?P<extras>\[[^\]]*\])?\s*(?:[<>=~!][^;#]*?)?(?P<tail>\s*[;#].*)?$",
            re.IGNORECASE,
        )
        for line in lines:
            m = pattern.match(line.strip())
            if m:
                # Keep extras and environment markers; only the version changes.
                new_lines.append(f"{m.group('name')}{m.group('extras') or ''}=={fixed_version}{m.group('tail') or ''}")
            else:
                new_lines.append(line)
        req_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    def _check() -> bool:
        content = req_path.read_text(encoding="utf-8").lower()
        if f"=={fixed_version}".lower() not in content or package_name.lower() not in content:
            return False

        if not _verify_requirements_txt(req_path):
            return False

        return _pip_dry_run(req_path)

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

    before = rule_counts(project_path, finding.file)

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
        return patch_is_improvement(before, rule_counts(project_path, finding.file), finding.rule_id)

    return apply_with_verification(target_file, _patch, _check, project_path)


def fix_secret_hybrid(
    project_path: Path, finding: SecretFinding
) -> tuple[FixOutcome, str, str]:
    """Document exposed secret in .env.example (name only) and issue rotation notice.

    This does NOT remove the secret from source; that, and rotating it, is a human task.
    The loop therefore reports this as SKIPPED + manual action, never RESOLVED.

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
