"""Unit tests for the weighted risk scoring engine."""

from supplyguard.sast.scanner import SastFinding
from supplyguard.scoring.engine import calculate_risk_score
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import VulnMatch


def test_scoring_weights_and_capping() -> None:
    # 1. Test clean state
    score_clean = calculate_risk_score([], [], [])
    assert score_clean.total_score == 0

    # 2. Test OSV weights: Critical +10, High +5, Medium +2
    vulns = [
        VulnMatch(package="pkg1", version="1.0", vuln_id="V1", severity="CRITICAL", summary="Crit"),
        VulnMatch(package="pkg2", version="1.0", vuln_id="V2", severity="HIGH", summary="High"),
        VulnMatch(package="pkg3", version="1.0", vuln_id="V3", severity="LOW", summary="Low"),
    ]
    score_vulns = calculate_risk_score(vulns, [], [])
    assert score_vulns.osv_score == 10 + 5 + 2
    assert score_vulns.total_score == 17

    # 3. Test Secrets weight: +15 per secret
    secrets = [
        SecretFinding(file="config.py", line=10, rule_id="aws-key", match_preview="AKI...XYZ"),
        SecretFinding(file="app.py", line=5, rule_id="api-token", match_preview="sec...123"),
    ]
    score_secrets = calculate_risk_score([], secrets, [])
    assert score_secrets.secrets_score == 30
    assert score_secrets.total_score == 30

    # 4. Test SAST weights: High +8, Med +3, Low +1
    sast = [
        SastFinding(file="a.py", line=1, rule_id="r1", severity="HIGH", cwe="CWE-89", message="SQLi"),
        SastFinding(file="b.py", line=2, rule_id="r2", severity="MEDIUM", cwe="CWE-295", message="TLS"),
    ]
    score_sast = calculate_risk_score([], [], sast)
    assert score_sast.sast_score == 8 + 3
    assert score_sast.total_score == 11

    # 5. Test Capping at 100
    many_secrets = [
        SecretFinding(file="sec.py", line=i, rule_id="key", match_preview="***")
        for i in range(10)
    ]
    score_capped = calculate_risk_score([], many_secrets, [])
    assert score_capped.secrets_score == 150
    assert score_capped.total_score == 100
