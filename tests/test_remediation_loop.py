"""Unit tests for the complete self-healing remediation loop."""

from pathlib import Path

from supplyguard.remediation.loop import remediate


def test_remediation_loop_dry_run(tmp_path: Path) -> None:
    # Setup test file with deterministic finding
    app_file = tmp_path / "app.py"
    app_file.write_text('from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n', encoding="utf-8")

    report = remediate(tmp_path, max_iterations=3, dry_run=True)

    assert report.resolved_count >= 1
    assert "debug=True" in app_file.read_text(encoding="utf-8")  # untouched due to dry-run


def test_remediation_loop_end_to_end_deterministic(tmp_path: Path) -> None:
    # Setup files with auto-fixable findings and manual finding
    app_file = tmp_path / "app.py"
    app_file.write_text(
        'import requests\n'
        'resp = requests.get("https://example.com", verify=False)\n'
        '# Unprotected admin\n'
        '@app.route("/admin/delete", methods=["DELETE"])\n'
        'def delete():\n'
        '    pass\n',
        encoding="utf-8",
    )

    report = remediate(tmp_path, max_iterations=3, dry_run=False, use_llm=False)

    # 1. verify=False should be resolved
    assert "verify=False" not in app_file.read_text(encoding="utf-8")
    assert report.resolved_count >= 1

    # 2. Manual required (unprotected admin route) should be left untouched
    assert report.manual_count >= 1
    assert any("admin" in m["rule"].lower() or "auth" in m["reason"].lower() for m in report.manual_findings)
