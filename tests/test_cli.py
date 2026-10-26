"""CLI-level tests for the scan quality gate."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from supplyguard import cli
from supplyguard.sbom.generator import Component
from supplyguard.secrets.scanner import SecretFinding
from supplyguard.vulns.osv_client import OsvUnavailableError, VulnMatch


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests==2.25.1\n", encoding="utf-8")
    monkeypatch.setattr(cli, "generate_sbom", lambda p, out=None: (out, [Component("requests", "2.25.1")]))
    monkeypatch.setattr(
        cli, "batch_query",
        lambda comps: [VulnMatch("requests", "2.25.1", "GHSA-test", "HIGH", "bad", "2.31.0")],
    )
    monkeypatch.setattr(
        cli, "scan_secrets",
        lambda *a, **k: [SecretFinding(file="examples/demo.py", line=3, rule_id="generic-api-key", match_preview="abc...xyz")],
    )
    monkeypatch.setattr(cli, "run_sast", lambda *a, **k: [])
    return tmp_path


def _scan(project: Path, *args: str):
    return CliRunner().invoke(
        cli.main, ["scan", str(project), "--format", "json", "--db-path", str(project / "sg.db"), *args]
    )


def test_ignored_findings_do_not_count_toward_the_gate(project: Path) -> None:
    # 1 HIGH vuln (5) + 1 secret (15) = 20 > threshold 10 → fail
    assert _scan(project, "--threshold", "10").exit_code == 1

    # Ignore the examples/ folder: only the HIGH vuln remains (5) ≤ 10 → pass
    (project / ".supplyguard.yml").write_text('ignore_paths:\n  - "examples/"\n', encoding="utf-8")
    result = _scan(project, "--threshold", "10")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["risk_score"] == 5


def test_dependency_findings_point_at_requirements_line(project: Path) -> None:
    data = json.loads(_scan(project).output)
    vuln = next(f for f in data["findings"] if f["source"] == "sbom_osv")
    assert vuln["file"] == "requirements.txt"
    assert vuln["line"] == 2


def test_osv_outage_exits_with_tool_error(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def down(_):
        raise OsvUnavailableError("down")

    monkeypatch.setattr(cli, "batch_query", down)
    assert _scan(project).exit_code == 2


def test_report_rebuilds_score_breakdown(project: Path) -> None:
    _scan(project)
    result = CliRunner().invoke(cli.main, ["report", "1", "--db-path", str(project / "sg.db"), "--format", "json"])
    breakdown = json.loads(result.output)["score_breakdown"]
    assert breakdown["osv"] == 5 and breakdown["secrets"] == 15


def test_scan_does_not_write_into_the_project(project: Path) -> None:
    _scan(project)
    assert not (project / "bom.json").exists()
