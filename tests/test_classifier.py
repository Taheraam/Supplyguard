"""Unit tests for the remediation fixability classifier."""

from supplyguard.remediation.classifier import FixStrategy, classify
from supplyguard.sast.scanner import SastFinding
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import VulnMatch


def test_classify_osv_vulnerabilities() -> None:
    with_fix = VulnMatch("pkg", "1.0", "CVE-1", "HIGH", "summary", fixed_version="2.0")
    no_fix = VulnMatch("pkg", "1.0", "CVE-2", "HIGH", "summary", fixed_version=None)

    assert classify(with_fix) == FixStrategy.DETERMINISTIC
    assert classify(no_fix) == FixStrategy.MANUAL_REQUIRED


def test_classify_secrets() -> None:
    secret = SecretFinding("app.py", 1, "api-key", "AKIA...XYZ")
    assert classify(secret) == FixStrategy.HYBRID


def test_classify_deterministic_sast() -> None:
    cwe_295 = SastFinding("a.py", 1, "ai-requests-verify-false", "MEDIUM", "CWE-295", "verify=False")
    cwe_489 = SastFinding("a.py", 1, "ai-flask-debug-true", "MEDIUM", "CWE-489", "debug=True")
    cwe_347 = SastFinding("a.py", 1, "ai-jwt-unverified-decode", "HIGH", "CWE-347", "jwt unverified")
    cwe_330 = SastFinding("a.py", 1, "ai-insecure-random-token", "MEDIUM", "CWE-330", "random token")

    assert classify(cwe_295) == FixStrategy.DETERMINISTIC
    assert classify(cwe_489) == FixStrategy.DETERMINISTIC
    assert classify(cwe_347) == FixStrategy.DETERMINISTIC
    assert classify(cwe_330) == FixStrategy.DETERMINISTIC


def test_classify_llm_assisted_sast() -> None:
    cwe_89 = SastFinding("a.py", 1, "ai-sql-injection-concat", "HIGH", "CWE-89", "SQLi")
    cwe_78 = SastFinding("a.py", 1, "ai-subprocess-shell-true", "HIGH", "CWE-78", "shell=True")
    cwe_916 = SastFinding("a.py", 1, "ai-weak-hash-md5-sha1", "MEDIUM", "CWE-916", "md5 hash")

    assert classify(cwe_89) == FixStrategy.LLM_ASSISTED
    assert classify(cwe_78) == FixStrategy.LLM_ASSISTED
    assert classify(cwe_916) == FixStrategy.LLM_ASSISTED


def test_classify_manual_required_sast() -> None:
    cwe_862 = SastFinding("a.py", 1, "ai-unprotected-admin-route", "MEDIUM", "CWE-862", "Missing auth")
    cwe_94 = SastFinding("a.py", 1, "ai-unsafe-eval-exec-pickle", "HIGH", "CWE-94", "eval on input")
    cwe_942 = SastFinding("a.py", 1, "ai-cors-wildcard-with-credentials", "MEDIUM", "CWE-942", "CORS wildcard")

    assert classify(cwe_862) == FixStrategy.MANUAL_REQUIRED
    assert classify(cwe_94) == FixStrategy.MANUAL_REQUIRED
    assert classify(cwe_942) == FixStrategy.MANUAL_REQUIRED


def test_manual_required_never_auto_touched() -> None:
    manual_findings = [
        SastFinding("a.py", 1, "ai-unprotected-admin-route", "MEDIUM", "CWE-862", "Missing auth"),
        SastFinding("a.py", 1, "ai-unsafe-eval-exec-pickle", "HIGH", "CWE-94", "eval on input"),
        SastFinding("a.py", 1, "ai-cors-wildcard-with-credentials", "MEDIUM", "CWE-942", "CORS wildcard"),
        VulnMatch("pkg", "1.0", "CVE-2", "HIGH", "summary", fixed_version=None),
    ]

    for finding in manual_findings:
        strategy = classify(finding)
        assert strategy == FixStrategy.MANUAL_REQUIRED
        # Safety assertion: strategy must not be deterministic or LLM assisted
        assert strategy not in (FixStrategy.DETERMINISTIC, FixStrategy.LLM_ASSISTED)
