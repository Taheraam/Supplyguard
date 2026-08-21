"""Unit tests for secrets detection and zero-leakage redaction."""

from pathlib import Path

from supplyguard.secrets.scanner import (
    redact_secret,
    scan_secrets,
)


def test_redact_secret() -> None:
    # Standard length secret
    raw = "AKIA1234567890ABCDEF"
    redacted = redact_secret(raw)
    assert redacted == "AKI...DEF"
    assert "1234567890ABC" not in redacted

    # Short secret
    short_raw = "12345"
    assert redact_secret(short_raw) == "***"


def test_secrets_scanner_detection_and_redaction(tmp_path: Path) -> None:
    # Create test file with fake credentials
    target_py = tmp_path / "config.py"
    target_py.write_text(
        '# Test config\nAWS_SECRET_KEY = "FAKE_KEY_FOR_TESTING_DO_NOT_USE"\n',
        encoding="utf-8",
    )

    findings = scan_secrets(tmp_path, allow_fallback=True)
    assert len(findings) >= 1

    finding = findings[0]
    assert finding.match_preview == "FAK...USE"
    assert "FAKE_KEY_FOR_TESTING_DO_NOT_USE" != finding.match_preview
    assert "DO_NOT_USE" not in finding.match_preview or finding.match_preview.endswith("USE")
