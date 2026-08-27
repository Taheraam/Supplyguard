"""Unit tests for the remediation fixability classifier."""

from supplyguard.remediation.classifier import (
    FixStrategy,
    classify,
    is_major_version_bump,
    is_test_file,
)
from supplyguard.sast.scanner import SastFinding
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import VulnMatch


def test_classify_osv_vulnerabilities() -> None:
    # Compatible minor bump on uncoupled package -> DETERMINISTIC
    compatible_fix = VulnMatch("urllib3", "1.26.5", "CVE-1", "HIGH", "summary", fixed_version="1.26.18")
    no_fix = VulnMatch("urllib3", "1.26.5", "CVE-2", "HIGH", "summary", fixed_version=None)

    assert classify(compatible_fix) == FixStrategy.DETERMINISTIC
    assert classify(no_fix) == FixStrategy.MANUAL_REQUIRED


def test_classify_osv_major_version_bump_is_manual() -> None:
    # Major version jump 1.x -> 2.x
    major_bump = VulnMatch("somepkg", "1.2.0", "CVE-1", "HIGH", "summary", fixed_version="2.0.0")
    # Pre-1.0 jump 0.3.x -> 1.x
    pre_1_jump = VulnMatch("somepkg", "0.3.13", "CVE-2", "HIGH", "summary", fixed_version="1.0.0")

    assert classify(major_bump) == FixStrategy.MANUAL_REQUIRED
    assert classify(pre_1_jump) == FixStrategy.MANUAL_REQUIRED


def test_classify_in_series_bump_is_deterministic() -> None:
    # In-series safe bumps should be auto-remediated
    lc_fix = VulnMatch("langchain", "0.3.13", "CVE-1", "HIGH", "summary", fixed_version="0.3.30")
    lc_core_fix = VulnMatch("langchain-core", "0.3.29", "CVE-2", "HIGH", "summary", fixed_version="0.3.85")

    assert classify(lc_fix) == FixStrategy.DETERMINISTIC
    assert classify(lc_core_fix) == FixStrategy.DETERMINISTIC


def test_classify_test_suite_paths_are_manual() -> None:
    # Findings in automated test suite files (tests/test_*.py) must be MANUAL_REQUIRED
    sast_in_tests = SastFinding(
        "tests/test_server.py", 12, "ai-requests-verify-false", "MEDIUM", "CWE-295", "verify=False"
    )
    assert classify(sast_in_tests) == FixStrategy.MANUAL_REQUIRED


def test_is_test_file() -> None:
    assert is_test_file("tests/test_app.py") is True
    assert is_test_file("tests/unit/test_auth.py") is True
    assert is_test_file("tests/conftest.py") is True
    assert is_test_file("examples/bad_pr/test.py") is False
    assert is_test_file("src/api/routes.py") is False
    assert is_test_file("app.py") is False


def test_is_major_version_bump() -> None:
    assert is_major_version_bump("1.0.0", "2.0.0") is True
    assert is_major_version_bump("0.3.13", "1.3.9") is True
    assert is_major_version_bump("0.3.13", "0.3.30") is False
    assert is_major_version_bump("1.2.0", "1.2.1") is False
    assert is_major_version_bump("1.2.0", "1.3.0") is False
    assert is_major_version_bump("2.25.1", "2.31.0") is False


def test_classify_secrets() -> None:
    secret = SecretFinding("app.py", 1, "api-key", "AKIA...XYZ")
    assert classify(secret) == FixStrategy.HYBRID


def test_classify_deterministic_sast() -> None:
    cwe_295 = SastFinding("src/client.py", 1, "ai-requests-verify-false", "MEDIUM", "CWE-295", "verify=False")
    cwe_489 = SastFinding("src/app.py", 1, "ai-flask-debug-true", "MEDIUM", "CWE-489", "debug=True")
    cwe_347 = SastFinding("src/auth.py", 1, "ai-jwt-unverified-decode", "HIGH", "CWE-347", "jwt unverified")
    cwe_330 = SastFinding("src/utils.py", 1, "ai-insecure-random-token", "MEDIUM", "CWE-330", "random token")

    assert classify(cwe_295) == FixStrategy.DETERMINISTIC
    assert classify(cwe_489) == FixStrategy.DETERMINISTIC
    assert classify(cwe_347) == FixStrategy.DETERMINISTIC
    assert classify(cwe_330) == FixStrategy.DETERMINISTIC


def test_classify_llm_assisted_sast() -> None:
    cwe_89 = SastFinding("src/db.py", 1, "ai-sql-injection-concat", "HIGH", "CWE-89", "SQLi")
    cwe_78 = SastFinding("src/runner.py", 1, "ai-subprocess-shell-true", "HIGH", "CWE-78", "shell=True")
    cwe_916 = SastFinding("src/hash.py", 1, "ai-weak-hash-md5-sha1", "MEDIUM", "CWE-916", "md5 hash")

    assert classify(cwe_89) == FixStrategy.LLM_ASSISTED
    assert classify(cwe_78) == FixStrategy.LLM_ASSISTED
    assert classify(cwe_916) == FixStrategy.LLM_ASSISTED


def test_classify_manual_required_sast() -> None:
    cwe_862 = SastFinding("src/routes.py", 1, "ai-unprotected-admin-route", "MEDIUM", "CWE-862", "Missing auth")
    cwe_94 = SastFinding("src/eval.py", 1, "ai-unsafe-eval-exec-pickle", "HIGH", "CWE-94", "eval on input")
    cwe_942 = SastFinding("src/cors.py", 1, "ai-cors-wildcard-with-credentials", "MEDIUM", "CWE-942", "CORS wildcard")

    assert classify(cwe_862) == FixStrategy.MANUAL_REQUIRED
    assert classify(cwe_94) == FixStrategy.MANUAL_REQUIRED
    assert classify(cwe_942) == FixStrategy.MANUAL_REQUIRED


def test_manual_required_never_auto_touched() -> None:
    manual_findings = [
        SastFinding("src/routes.py", 1, "ai-unprotected-admin-route", "MEDIUM", "CWE-862", "Missing auth"),
        SastFinding("src/eval.py", 1, "ai-unsafe-eval-exec-pickle", "HIGH", "CWE-94", "eval on input"),
        SastFinding("src/cors.py", 1, "ai-cors-wildcard-with-credentials", "MEDIUM", "CWE-942", "CORS wildcard"),
        VulnMatch("pkg", "1.0", "CVE-2", "HIGH", "summary", fixed_version=None),
        VulnMatch("pkg", "1.0.0", "CVE-3", "HIGH", "summary", fixed_version="2.0.0"),
    ]

    for finding in manual_findings:
        strategy = classify(finding)
        assert strategy == FixStrategy.MANUAL_REQUIRED
        # Safety assertion: strategy must not be deterministic or LLM assisted
        assert strategy not in (FixStrategy.DETERMINISTIC, FixStrategy.LLM_ASSISTED)

