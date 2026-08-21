"""Unit tests for CycloneDX SBOM generator module."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from supplyguard.sbom.generator import (
    _parse_cyclonedx_json,
    generate_sbom,
)


def test_parse_cyclonedx_json(tmp_path: Path) -> None:
    sbom_file = tmp_path / "test_bom.json"
    data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "name": "flask",
                "version": "2.0.1",
                "purl": "pkg:pypi/flask@2.0.1",
            },
            {
                "name": "requests",
                "version": "2.25.1",
                "purl": "pkg:pypi/requests@2.25.1",
            },
        ],
    }
    sbom_file.write_text(json.dumps(data), encoding="utf-8")
    components = _parse_cyclonedx_json(sbom_file)

    assert len(components) == 2
    assert components[0].name == "flask"
    assert components[0].version == "2.0.1"
    assert components[1].name == "requests"


def test_generate_sbom_missing_requirements(tmp_path: Path) -> None:
    out_file, components = generate_sbom(tmp_path)
    assert out_file.exists()
    assert components == []


@patch("subprocess.run")
def test_generate_sbom_success(mock_run: MagicMock, tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==2.0.1\n", encoding="utf-8")
    out_file = tmp_path / "bom.json"

    def side_effect(cmd, **kwargs):
        # simulate cyclonedx outputting bom.json
        out_file.write_text(
            json.dumps({"components": [{"name": "flask", "version": "2.0.1"}]}),
            encoding="utf-8",
        )
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = ""
        mock_res.stderr = ""
        return mock_res

    mock_run.side_effect = side_effect

    res_path, components = generate_sbom(tmp_path, out_file)
    assert res_path == out_file
    assert len(components) == 1
    assert components[0].name == "flask"
    assert components[0].version == "2.0.1"
