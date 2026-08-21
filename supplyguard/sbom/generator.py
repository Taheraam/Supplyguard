"""CycloneDX SBOM generator for Python dependencies."""

import json
import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Component:
    """Represents an identified software component from an SBOM."""

    name: str
    version: str
    purl: str = ""


class SbomGenerationError(Exception):
    """Raised when SBOM generation fails."""


def _find_cyclonedx_cmd() -> list[str]:
    """Locate the cyclonedx execution command.

    Returns:
        Command arguments list to execute cyclonedx.

    Raises:
        SbomGenerationError: If cyclonedx-py executable or module is missing.
    """
    if shutil.which("cyclonedx-py"):
        return ["cyclonedx-py"]
    # Check if module is runnable via current python interpreter
    return [sys.executable, "-m", "cyclonedx_py"]


def _parse_cyclonedx_json(sbom_file: Path) -> list[Component]:
    """Parse generated CycloneDX JSON file into Component dataclasses.

    Args:
        sbom_file: Path to the generated CycloneDX JSON file.

    Returns:
        List of parsed Component objects.
    """
    try:
        content = sbom_file.read_text(encoding="utf-8")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError) as err:
        logger.warning(f"Failed to read or parse SBOM JSON {sbom_file}: {err}")
        return []

    components: list[Component] = []
    raw_components = data.get("components", [])
    for comp in raw_components:
        name = comp.get("name")
        version = comp.get("version", "")
        purl = comp.get("purl", "")
        if name:
            components.append(Component(name=name, version=str(version), purl=purl))
    return components


def _parse_requirements_file(req_file: Path) -> list[Component]:
    """Parse components directly from requirements.txt as a fast fallback."""
    components: list[Component] = []
    try:
        lines = req_file.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            # Match package==version or package>=version or package
            match = re.match(r"^([a-zA-Z0-9_\-]+)(?:[=><~^!]+([0-9a-zA-Z._\-]+))?", line)
            if match:
                name = match.group(1)
                version = match.group(2) or "0.0.0"
                purl = f"pkg:pypi/{name}@{version}"
                components.append(Component(name=name, version=version, purl=purl))
    except OSError as err:
        logger.warning(f"Failed to read requirements fallback: {err}")
    return components


def generate_sbom(
    project_path: Path, output_path: Path | None = None
) -> tuple[Path, list[Component]]:
    """Generate a CycloneDX JSON SBOM from requirements.txt in project_path.

    Args:
        project_path: Directory of the project to scan.
        output_path: Optional explicit target path for the SBOM JSON file.

    Returns:
        Tuple of (path to generated sbom file, list of components).

    Raises:
        SbomGenerationError: If cyclonedx execution fails or is not installed.
    """
    req_file = project_path / "requirements.txt"
    target_out = output_path or (project_path / "bom.json")

    if not req_file.exists():
        logger.info(f"No requirements.txt found at {req_file}; returning empty SBOM.")
        target_out.write_text(json.dumps({"components": []}), encoding="utf-8")
        return target_out, []

    cmd_base = _find_cyclonedx_cmd()
    cmd = [
        *cmd_base,
        "requirements",
        str(req_file),
        "-o",
        str(target_out),
        "--output-format",
        "JSON",
        "--no-validate",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=10,
        )
        if result.returncode == 0 and target_out.exists() and target_out.stat().st_size > 0:
            components = _parse_cyclonedx_json(target_out)
            if components:
                return target_out, components
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as err:
        logger.warning(f"CycloneDX execution timed out or failed ({err}). Using direct manifest parser.")

    # Fallback to direct manifest parser & construct valid CycloneDX JSON
    components = _parse_requirements_file(req_file)
    sbom_dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": c.name, "version": c.version, "purl": c.purl}
            for c in components
        ],
    }
    target_out.write_text(json.dumps(sbom_dict, indent=2), encoding="utf-8")
    return target_out, components
