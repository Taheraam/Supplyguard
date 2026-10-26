"""Unit tests for the safety verifier's rollback guarantees."""

from pathlib import Path

from supplyguard.remediation.verifier import FixOutcome, apply_with_verification


def _boom() -> bool:
    raise RuntimeError("scanner crashed mid-check")


def test_rollback_when_check_raises(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("a = 1\n", encoding="utf-8")

    outcome, diff = apply_with_verification(target, lambda: target.write_text("a = 2\n"), _boom, None)

    assert outcome == FixOutcome.FIX_FAILED
    assert "Verification crashed" in diff
    assert target.read_text(encoding="utf-8") == "a = 1\n"


def test_rollback_on_syntax_error(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("a = 1\n", encoding="utf-8")

    outcome, _ = apply_with_verification(target, lambda: target.write_text("a = (\n"), lambda: True, None)

    assert outcome == FixOutcome.FIX_FAILED
    assert target.read_text(encoding="utf-8") == "a = 1\n"


def test_new_file_removed_on_failure(tmp_path: Path) -> None:
    target = tmp_path / ".env.example"

    outcome, _ = apply_with_verification(target, lambda: target.write_text("X=\n"), lambda: False, None)

    assert outcome == FixOutcome.FIX_FAILED
    assert not target.exists()


def test_resolved_returns_diff(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("debug = True\n", encoding="utf-8")

    outcome, diff = apply_with_verification(target, lambda: target.write_text("debug = False\n"), lambda: True, None)

    assert outcome == FixOutcome.RESOLVED
    assert "-debug = True" in diff and "+debug = False" in diff
