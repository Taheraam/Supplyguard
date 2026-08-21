"""Tests for SupplyGuard output formatters (table, JSON, SARIF v2.1.0)."""

import json

import pytest

from supplyguard.formatters import ScanOutput, format_output
from supplyguard.scoring.engine import ScoreBreakdown


@pytest.fixture()
def sample_scan_output() -> ScanOutput:
    """Create a sample ScanOutput for testing."""
    return ScanOutput(
        scan_id=1,
        project_path="/test/project",
        risk_score=65,
        score_breakdown=ScoreBreakdown(
            total_score=65,
            osv_score=30,
            secrets_score=15,
            sast_score=20,
            findings_by_severity={"CRITICAL": 1, "HIGH": 3, "MEDIUM": 2, "LOW": 0},
            findings_by_source={"sbom_osv": 3, "secrets": 1, "sast": 2},
        ),
        components_count=5,
        findings=[
            {
                "source": "sbom_osv",
                "severity": "CRITICAL",
                "file": "flask==2.0.1",
                "line": 1,
                "rule_id": "GHSA-m2qf-hxjv-5gpq",
                "cwe": "CWE-1395",
                "message": "Remote code execution in flask",
            },
            {
                "source": "secrets",
                "severity": "CRITICAL",
                "file": "app.py",
                "line": 15,
                "rule_id": "generic-api-key",
                "cwe": "CWE-798",
                "message": "Hardcoded API key detected",
            },
            {
                "source": "sast",
                "severity": "HIGH",
                "file": "app.py",
                "line": 28,
                "rule_id": "ai-sql-injection-concat",
                "cwe": "CWE-89",
                "message": "SQL query constructed via string concatenation",
            },
        ],
        started_at="2026-01-01T00:00:00",
        finished_at="2026-01-01T00:00:10",
    )


class TestJsonFormat:
    """Tests for JSON output format."""

    def test_json_is_valid(self, sample_scan_output: ScanOutput) -> None:
        """JSON output is valid and parseable."""
        result = format_output("json", sample_scan_output)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_json_has_required_fields(self, sample_scan_output: ScanOutput) -> None:
        """JSON output contains all required top-level fields."""
        parsed = json.loads(format_output("json", sample_scan_output))
        assert parsed["tool"] == "SupplyGuard"
        assert parsed["risk_score"] == 65
        assert parsed["scan_id"] == 1
        assert parsed["components_count"] == 5
        assert parsed["findings_count"] == 3
        assert len(parsed["findings"]) == 3

    def test_json_score_breakdown(self, sample_scan_output: ScanOutput) -> None:
        """JSON output includes detailed score breakdown."""
        parsed = json.loads(format_output("json", sample_scan_output))
        breakdown = parsed["score_breakdown"]
        assert breakdown["osv"] == 30
        assert breakdown["secrets"] == 15
        assert breakdown["sast"] == 20


class TestSarifFormat:
    """Tests for SARIF v2.1.0 output format."""

    def test_sarif_is_valid_json(self, sample_scan_output: ScanOutput) -> None:
        """SARIF output is valid JSON."""
        result = format_output("sarif", sample_scan_output)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_sarif_schema_version(self, sample_scan_output: ScanOutput) -> None:
        """SARIF output declares correct schema and version."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        assert parsed["version"] == "2.1.0"
        assert "$schema" in parsed

    def test_sarif_has_runs(self, sample_scan_output: ScanOutput) -> None:
        """SARIF output contains runs array with tool metadata."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        assert len(parsed["runs"]) == 1
        run = parsed["runs"][0]
        assert run["tool"]["driver"]["name"] == "SupplyGuard"
        assert "rules" in run["tool"]["driver"]

    def test_sarif_results_count(self, sample_scan_output: ScanOutput) -> None:
        """SARIF results count matches findings count."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        results = parsed["runs"][0]["results"]
        assert len(results) == 3

    def test_sarif_result_structure(self, sample_scan_output: ScanOutput) -> None:
        """Each SARIF result has required fields: ruleId, level, message, locations."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        result = parsed["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert result["level"] in ("error", "warning", "note")
        assert "message" in result
        assert "text" in result["message"]
        assert "locations" in result
        assert len(result["locations"]) >= 1

    def test_sarif_artifact_location(self, sample_scan_output: ScanOutput) -> None:
        """SARIF locations include artifactLocation with uri and region."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        location = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "artifactLocation" in location
        assert "uri" in location["artifactLocation"]
        assert "region" in location
        assert "startLine" in location["region"]

    def test_sarif_rules_deduplicated(self, sample_scan_output: ScanOutput) -> None:
        """SARIF rules are deduplicated by rule ID."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids)), "Rule IDs should be unique"

    def test_sarif_security_severity(self, sample_scan_output: ScanOutput) -> None:
        """SARIF results include security-severity property for GitHub Security tab."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        result = parsed["runs"][0]["results"][0]
        assert "security-severity" in result["properties"]

    def test_sarif_invocations(self, sample_scan_output: ScanOutput) -> None:
        """SARIF includes invocation metadata."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        invocations = parsed["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_sarif_supplyguard_properties(self, sample_scan_output: ScanOutput) -> None:
        """SARIF run includes custom SupplyGuard properties (riskScore, scanId)."""
        parsed = json.loads(format_output("sarif", sample_scan_output))
        props = parsed["runs"][0]["properties"]
        assert props["supplyguard:riskScore"] == 65
        assert props["supplyguard:scanId"] == 1


class TestTableFormat:
    """Tests for Rich table output."""

    def test_table_returns_empty_string(self, sample_scan_output: ScanOutput) -> None:
        """Table format returns empty string (prints to console directly)."""
        result = format_output("table", sample_scan_output)
        assert result == ""


class TestFormatDispatch:
    """Tests for format_output dispatch."""

    def test_unknown_format_raises(self, sample_scan_output: ScanOutput) -> None:
        """Unknown format name raises ValueError."""
        with pytest.raises(ValueError, match="Unknown format"):
            format_output("xml", sample_scan_output)
