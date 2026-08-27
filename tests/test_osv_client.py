"""Unit tests for OSV.dev REST client module."""


import responses

from supplyguard.sbom.generator import Component
from supplyguard.vulns.osv_client import (
    OSV_BATCH_URL,
    OSV_VULN_URL,
    batch_query,
)


@responses.activate
def test_batch_query_with_vulnerability_match() -> None:
    # Mock batch query response
    batch_response_payload = {
        "results": [
            {
                "vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}],
            }
        ]
    }
    responses.add(
        responses.POST,
        OSV_BATCH_URL,
        json=batch_response_payload,
        status=200,
    )

    # Mock vulnerability details response
    vuln_detail_payload = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Critical Vulnerability in Requests",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.31.0"}],
                    }
                ],
            }
        ],
    }
    responses.add(
        responses.GET,
        f"{OSV_VULN_URL}/GHSA-xxxx-yyyy-zzzz",
        json=vuln_detail_payload,
        status=200,
    )

    components = [Component(name="requests", version="2.25.1")]
    matches = batch_query(components)

    assert len(matches) == 1
    m = matches[0]
    assert m.package == "requests"
    assert m.version == "2.25.1"
    assert m.vuln_id == "GHSA-xxxx-yyyy-zzzz"
    assert m.severity == "CRITICAL"
    assert m.fixed_version == "2.31.0"
    assert "Critical Vulnerability" in m.summary


def test_batch_query_empty_components() -> None:
    assert batch_query([]) == []


def test_select_minimum_compatible_version() -> None:
    from supplyguard.vulns.osv_client import select_minimum_compatible_version

    # Patch bump preferred over minor and major
    assert select_minimum_compatible_version("0.3.13", ["1.3.9", "0.4.0", "0.3.14"]) == "0.3.14"

    # Minor bump preferred over major bump
    assert select_minimum_compatible_version("0.3.13", ["1.3.9", "0.4.0"]) == "0.4.0"

    # Same major, lowest patch
    assert select_minimum_compatible_version("1.2.0", ["2.0.0", "1.3.0", "1.2.5"]) == "1.2.5"

    # Fallback to lowest newer major when no same major exists
    assert select_minimum_compatible_version("1.2.0", ["3.0.0", "2.0.0"]) == "2.0.0"

    # Empty candidate list
    assert select_minimum_compatible_version("1.0.0", []) is None

