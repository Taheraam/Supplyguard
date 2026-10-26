"""SupplyGuard: AI-Aware Software Supply Chain Security Scanner & Remediation Engine."""

from importlib.metadata import PackageNotFoundError, version

# Single source of truth is pyproject.toml. This file, the CLI and the SARIF/JSON
# output previously hardcoded three different versions (0.2.0, 0.3.2, 0.3.4).
try:
    __version__ = version("supplyguard")
except PackageNotFoundError:  # running from a source checkout that was never installed
    __version__ = "0.0.0+unknown"
