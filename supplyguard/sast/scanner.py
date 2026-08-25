"""SAST scanner running Semgrep with custom AI-code-smell rules and Python fallback."""

import ast
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_RULES_PATH = (
    Path(__file__).parent / "rules" / "ai-code-smells.yml"
)


@dataclass
class SastFinding:
    """Represents a static analysis finding."""

    file: str
    line: int
    rule_id: str
    severity: str
    cwe: str
    message: str


class SemgrepExecutionError(Exception):
    """Raised when Semgrep static analysis fails."""


def _path_matches_ignore(rel_path: str, ignore_patterns: list[str]) -> bool:
    """Check if a relative path matches any of the ignore patterns.

    Args:
        rel_path: Relative file path to check.
        ignore_patterns: List of patterns from .supplyguard.yml ignore_paths.

    Returns:
        True if the path should be ignored.
    """
    normalized = rel_path.replace("\\", "/")
    for pattern in ignore_patterns:
        clean = pattern.strip().rstrip("/")
        if normalized.startswith(clean + "/") or normalized == clean:
            return True
        if "/" not in clean and clean in normalized.split("/"):
            return True
    return False


def _run_semgrep_cli(
    project_path: Path, rules_path: Path, include_public: bool = False
) -> list[SastFinding]:
    """Execute Semgrep CLI against project_path."""
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        raise SemgrepExecutionError(
            "Semgrep is not installed or not found on PATH. "
            "Install Semgrep via 'pip install semgrep' or see https://semgrep.dev"
        )

    cmd = [
        semgrep_bin,
        f"--config={rules_path}",
        "--json",
        str(project_path),
    ]
    if include_public:
        cmd.append("--config=p/security-audit")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )

    findings: list[SastFinding] = []
    if result.stdout:
        try:
            data = json.loads(result.stdout)
            for res in data.get("results", []):
                extra = res.get("extra", {})
                metadata = extra.get("metadata", {})
                findings.append(
                    SastFinding(
                        file=res.get("path", ""),
                        line=int(res.get("start", {}).get("line", 1)),
                        rule_id=res.get("check_id", "sast-finding"),
                        severity=extra.get("severity", "WARNING").upper(),
                        cwe=metadata.get("cwe", "CWE-Unknown"),
                        message=extra.get("message", "Potential security issue"),
                    )
                )
        except json.JSONDecodeError as err:
            logger.warning(f"Could not parse Semgrep JSON output: {err}")

    return findings


class _FallbackAstVisitor(ast.NodeVisitor):
    """AST visitor implementing the 10 AI-code-smell checks for fallback execution."""

    def __init__(self, rel_path: str, lines: list[str]) -> None:
        self.rel_path = rel_path
        self.lines = lines
        self.findings: list[SastFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        # Rule 1: SQL Injection concat/f-string in execute()
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                self.findings.append(
                    SastFinding(
                        file=self.rel_path,
                        line=node.lineno,
                        rule_id="ai-sql-injection-concat",
                        severity="HIGH",
                        cwe="CWE-89",
                        message="SQL query constructed via string formatting/concatenation",
                    )
                )

        # Rule 3: eval/exec/pickle.loads on variable
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if node.args and not isinstance(node.args[0], ast.Constant):
                self.findings.append(
                    SastFinding(
                        file=self.rel_path,
                        line=node.lineno,
                        rule_id="ai-unsafe-eval-exec-pickle",
                        severity="HIGH",
                        cwe="CWE-94",
                        message="Dynamic code execution on non-literal variable",
                    )
                )
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "loads" and isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
            self.findings.append(
                SastFinding(
                    file=self.rel_path,
                    line=node.lineno,
                    rule_id="ai-unsafe-eval-exec-pickle",
                    severity="HIGH",
                    cwe="CWE-502",
                    message="Unsafe pickle.loads deserialization",
                )
            )

        # Rule 4: subprocess with shell=True
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "call", "check_output"):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True and node.args and not isinstance(node.args[0], ast.Constant):
                    self.findings.append(
                        SastFinding(
                            file=self.rel_path,
                            line=node.lineno,
                            rule_id="ai-subprocess-shell-true",
                            severity="HIGH",
                            cwe="CWE-78",
                            message="subprocess call with shell=True on dynamic arguments",
                        )
                    )

        # Rule 5: requests with verify=False
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self.findings.append(
                    SastFinding(
                        file=self.rel_path,
                        line=node.lineno,
                        rule_id="ai-requests-verify-false",
                        severity="MEDIUM",
                        cwe="CWE-295",
                        message="TLS verification explicitly disabled with verify=False",
                    )
                )

        # Rule 6: app.run(debug=True)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append(
                        SastFinding(
                            file=self.rel_path,
                            line=node.lineno,
                            rule_id="ai-flask-debug-true",
                            severity="MEDIUM",
                            cwe="CWE-489",
                            message="Flask application executed with debug=True",
                        )
                    )

        # Rule 7: hashlib.md5 / sha1
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("md5", "sha1") and isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
            self.findings.append(
                SastFinding(
                    file=self.rel_path,
                    line=node.lineno,
                    rule_id="ai-weak-hash-md5-sha1",
                    severity="MEDIUM",
                    cwe="CWE-916",
                    message="Weak cryptographic hash function (MD5/SHA1) used",
                )
            )

        # Rule 8: jwt.decode with verify=False or verify_signature=False
        if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self.findings.append(
                        SastFinding(
                            file=self.rel_path,
                            line=node.lineno,
                            rule_id="ai-jwt-unverified-decode",
                            severity="HIGH",
                            cwe="CWE-347",
                            message="JWT decode with signature verification disabled",
                        )
                    )

        # Rule 10: random.choice / randint / random for tokens
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("choice", "randint", "random") and isinstance(node.func.value, ast.Name) and node.func.value.id == "random":
            line_text = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
            if any(word in line_text for word in ("token", "secret", "password", "session", "key", "auth")):
                self.findings.append(
                    SastFinding(
                        file=self.rel_path,
                        line=node.lineno,
                        rule_id="ai-insecure-random-token",
                        severity="MEDIUM",
                        cwe="CWE-330",
                        message="Insecure random module used for security-sensitive token/credential",
                    )
                )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Rule 2: Unprotected delete/update/admin route in Flask
        route_decorator = None
        has_auth = False
        is_sensitive = False

        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "route":
                route_decorator = dec
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, ast.List):
                        for el in kw.value.elts:
                            if isinstance(el, ast.Constant) and str(el.value).upper() in ("DELETE", "POST", "PUT"):
                                is_sensitive = True
            elif isinstance(dec, ast.Name) and any(w in dec.id.lower() for w in ("auth", "login")):
                has_auth = True
            elif isinstance(dec, ast.Call):
                func_name = ""
                if isinstance(dec.func, ast.Name):
                    func_name = dec.func.id.lower()
                elif isinstance(dec.func, ast.Attribute):
                    func_name = dec.func.attr.lower()
                if any(w in func_name for w in ("auth", "login")):
                    has_auth = True

        if any(w in node.name.lower() for w in ("admin", "delete", "remove", "drop", "wipe")):
            is_sensitive = True

        if route_decorator and is_sensitive and not has_auth:
            self.findings.append(
                SastFinding(
                    file=self.rel_path,
                    line=node.lineno,
                    rule_id="ai-unprotected-admin-route",
                    severity="MEDIUM",
                    cwe="CWE-862",
                    message="Sensitive administrative/delete route without authentication decorator",
                )
            )

        self.generic_visit(node)


def _fallback_sast_scan(project_path: Path, ignore_paths: list[str] | None = None) -> list[SastFinding]:
    """Pure-Python AST analysis fallback when Semgrep CLI is unavailable.

    Args:
        project_path: Path to target project.
        ignore_paths: Path patterns to exclude from scanning.

    Returns:
        List of SastFinding instances.
    """
    import os

    excluded = ignore_paths or []
    findings: list[SastFinding] = []
    ignore_dirs = {".git", ".venv", "node_modules", "__pycache__", ".agent", ".pytest_cache"}

    for root, dirs, files in os.walk(str(project_path)):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if not f.endswith(".py"):
                continue
            py_file = Path(root) / f
            rel_str = str(py_file.relative_to(project_path))

            # Skip files matching any ignore_paths pattern
            if _path_matches_ignore(rel_str, excluded):
                continue

            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
                lines = source.splitlines()
            except (SyntaxError, OSError):
                continue

            rel_str = str(py_file.relative_to(project_path))
            visitor = _FallbackAstVisitor(rel_str, lines)
            visitor.visit(tree)
            findings.extend(visitor.findings)

            # Rule 9: Check CORS wildcard with credentials via regex
            for idx, line in enumerate(lines, start=1):
                if "Access-Control-Allow-Origin" in line and "*" in line:
                    nearby = "".join(lines[max(0, idx - 3) : min(len(lines), idx + 3)])
                    if "credentials" in nearby.lower() and "true" in nearby.lower():
                        findings.append(
                            SastFinding(
                                file=rel_str,
                                line=idx,
                                rule_id="ai-cors-wildcard-with-credentials",
                                severity="MEDIUM",
                                cwe="CWE-942",
                                message="CORS wildcard origin configured with credentials enabled",
                            )
                        )

    return findings


def run_sast(
    project_path: Path,
    rules_path: Path | None = None,
    include_public_rules: bool = False,
    allow_fallback: bool = True,
    ignore_paths: list[str] | None = None,
) -> list[SastFinding]:
    """Execute SAST scan against project_path using Semgrep or fallback parser.

    Args:
        project_path: Path to target project.
        rules_path: Optional path to custom Semgrep rules YAML.
        include_public_rules: Whether to also run p/security-audit rules.
        allow_fallback: Fallback to AST scanner if semgrep is unavailable.
        ignore_paths: Path patterns to exclude from scanning.

    Returns:
        List of SastFinding instances.
    """
    target_rules = rules_path or DEFAULT_RULES_PATH
    try:
        findings = _run_semgrep_cli(project_path, target_rules, include_public_rules)
    except SemgrepExecutionError as err:
        if allow_fallback:
            logger.debug(f"{err}. Using internal AST SAST scanner.")
            return _fallback_sast_scan(project_path, ignore_paths=ignore_paths)
        raise

    # Filter semgrep results by ignore_paths too
    if ignore_paths:
        findings = [
            f for f in findings
            if not _path_matches_ignore(f.file, ignore_paths)
        ]
    return findings
