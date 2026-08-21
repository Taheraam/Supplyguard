"""Project configuration loader for .supplyguard.yml files."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

CONFIG_FILENAME = ".supplyguard.yml"

# Default config template written by `supplyguard init`
DEFAULT_CONFIG_TEMPLATE = """\
# SupplyGuard Configuration
# https://github.com/supplyguard/supplyguard

# Risk score threshold for CI gates (0-100).
# `supplyguard scan` exits with code 1 if the score exceeds this value.
threshold: 100

# Default output format: table | json | sarif
format: table

# Minimum severity level to report. Findings below this are filtered out.
# Options: CRITICAL, HIGH, MEDIUM, LOW
severity_minimum: LOW

# Paths to exclude from scanning (glob patterns).
ignore_paths:
  - ".venv/"
  - "node_modules/"
  - ".git/"
  - "__pycache__/"

# Rule IDs or CWE IDs to suppress (e.g., CWE-489 for debug=True in dev).
ignore_rules: []
"""


@dataclass
class SupplyGuardConfig:
    """Resolved configuration for a SupplyGuard scan.

    Attributes:
        threshold: Risk score threshold for CI exit codes (0-100).
        format: Output format (table, json, sarif).
        severity_minimum: Minimum severity to include in results.
        ignore_paths: Glob patterns for paths to skip during scanning.
        ignore_rules: Rule IDs or CWE IDs to suppress from output.
    """

    threshold: int = 100
    format: str = "table"
    severity_minimum: str = "LOW"
    ignore_paths: list[str] = field(default_factory=lambda: [".venv/", "node_modules/", ".git/", "__pycache__/"])
    ignore_rules: list[str] = field(default_factory=list)


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def severity_meets_minimum(severity: str, minimum: str) -> bool:
    """Check if a finding's severity meets the configured minimum.

    Args:
        severity: The finding's severity (e.g., "HIGH").
        minimum: The minimum severity threshold (e.g., "MEDIUM").

    Returns:
        True if severity >= minimum.
    """
    return _SEVERITY_ORDER.get(severity.upper(), 0) >= _SEVERITY_ORDER.get(minimum.upper(), 0)


def load_config(project_path: Path, cli_overrides: dict[str, Any] | None = None) -> SupplyGuardConfig:
    """Load configuration from .supplyguard.yml with CLI flag overrides.

    Resolution order (highest priority first):
        1. CLI flags (--format, --threshold, etc.)
        2. .supplyguard.yml in project root
        3. Built-in defaults

    Args:
        project_path: Path to the project root to search for config.
        cli_overrides: Dict of CLI flag values that override config file.

    Returns:
        Resolved SupplyGuardConfig instance.
    """
    config = SupplyGuardConfig()
    config_file = Path(project_path) / CONFIG_FILENAME

    if config_file.is_file():
        try:
            raw = yaml.safe_load(config_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                if "threshold" in raw:
                    config.threshold = int(raw["threshold"])
                if "format" in raw:
                    config.format = str(raw["format"])
                if "severity_minimum" in raw:
                    config.severity_minimum = str(raw["severity_minimum"]).upper()
                if "ignore_paths" in raw and isinstance(raw["ignore_paths"], list):
                    config.ignore_paths = [str(p) for p in raw["ignore_paths"]]
                if "ignore_rules" in raw and isinstance(raw["ignore_rules"], list):
                    config.ignore_rules = [str(r) for r in raw["ignore_rules"]]
                logger.info(f"Loaded config from {config_file}")
        except (yaml.YAMLError, ValueError, OSError) as err:
            logger.warning(f"Failed to parse {config_file}: {err}. Using defaults.")

    # CLI overrides take highest priority
    if cli_overrides:
        if cli_overrides.get("threshold") is not None:
            config.threshold = int(cli_overrides["threshold"])
        if cli_overrides.get("format") is not None:
            config.format = str(cli_overrides["format"])

    return config


def write_default_config(project_path: Path) -> Path:
    """Write the default .supplyguard.yml template to a project directory.

    Args:
        project_path: Target project directory.

    Returns:
        Path to the created config file.

    Raises:
        FileExistsError: If .supplyguard.yml already exists.
    """
    config_file = Path(project_path) / CONFIG_FILENAME
    if config_file.exists():
        raise FileExistsError(f"{CONFIG_FILENAME} already exists at {config_file}")
    config_file.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
    return config_file
