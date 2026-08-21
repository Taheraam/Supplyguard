"""Tests for SupplyGuard config loader (.supplyguard.yml)."""

import textwrap
from pathlib import Path

import pytest

from supplyguard.config import (
    SupplyGuardConfig,
    load_config,
    severity_meets_minimum,
    write_default_config,
)


class TestSeverityFilter:
    """Tests for severity_meets_minimum."""

    def test_critical_meets_any(self) -> None:
        """CRITICAL meets any minimum."""
        assert severity_meets_minimum("CRITICAL", "CRITICAL")
        assert severity_meets_minimum("CRITICAL", "LOW")

    def test_low_does_not_meet_high(self) -> None:
        """LOW does not meet HIGH minimum."""
        assert not severity_meets_minimum("LOW", "HIGH")

    def test_medium_meets_medium(self) -> None:
        """MEDIUM meets MEDIUM minimum."""
        assert severity_meets_minimum("MEDIUM", "MEDIUM")

    def test_case_insensitive(self) -> None:
        """Severity comparison is case insensitive."""
        assert severity_meets_minimum("high", "MEDIUM")


class TestLoadConfig:
    """Tests for load_config."""

    def test_defaults_when_no_file(self, tmp_path: Path) -> None:
        """Returns defaults when no config file exists."""
        config = load_config(tmp_path)
        assert config.threshold == 100
        assert config.format == "table"
        assert config.severity_minimum == "LOW"

    def test_loads_from_yaml(self, tmp_path: Path) -> None:
        """Loads values from .supplyguard.yml file."""
        config_file = tmp_path / ".supplyguard.yml"
        config_file.write_text(
            textwrap.dedent("""\
                threshold: 40
                format: sarif
                severity_minimum: HIGH
                ignore_paths:
                  - "tests/"
                ignore_rules:
                  - "CWE-489"
            """),
            encoding="utf-8",
        )
        config = load_config(tmp_path)
        assert config.threshold == 40
        assert config.format == "sarif"
        assert config.severity_minimum == "HIGH"
        assert "tests/" in config.ignore_paths
        assert "CWE-489" in config.ignore_rules

    def test_cli_overrides_file(self, tmp_path: Path) -> None:
        """CLI flags override config file values."""
        config_file = tmp_path / ".supplyguard.yml"
        config_file.write_text("threshold: 40\nformat: sarif\n", encoding="utf-8")

        config = load_config(tmp_path, cli_overrides={"threshold": 80, "format": "json"})
        assert config.threshold == 80
        assert config.format == "json"

    def test_partial_cli_overrides(self, tmp_path: Path) -> None:
        """Partial CLI overrides only affect specified values."""
        config_file = tmp_path / ".supplyguard.yml"
        config_file.write_text("threshold: 40\nformat: sarif\n", encoding="utf-8")

        config = load_config(tmp_path, cli_overrides={"format": "json"})
        assert config.threshold == 40  # From file
        assert config.format == "json"  # From CLI

    def test_invalid_yaml_uses_defaults(self, tmp_path: Path) -> None:
        """Invalid YAML falls back to defaults gracefully."""
        config_file = tmp_path / ".supplyguard.yml"
        config_file.write_text("{{invalid yaml: [", encoding="utf-8")
        config = load_config(tmp_path)
        assert config.threshold == 100  # Default


class TestWriteConfig:
    """Tests for write_default_config."""

    def test_creates_config_file(self, tmp_path: Path) -> None:
        """Creates .supplyguard.yml with default content."""
        result = write_default_config(tmp_path)
        assert result.exists()
        assert result.name == ".supplyguard.yml"
        content = result.read_text(encoding="utf-8")
        assert "threshold" in content
        assert "ignore_paths" in content

    def test_raises_if_exists(self, tmp_path: Path) -> None:
        """Raises FileExistsError if config already exists."""
        (tmp_path / ".supplyguard.yml").write_text("existing", encoding="utf-8")
        with pytest.raises(FileExistsError):
            write_default_config(tmp_path)
