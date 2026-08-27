"""OSV.dev REST API client for OSS vulnerability correlation."""

import logging
from dataclasses import dataclass
from typing import Any

import requests
from requests.exceptions import RequestException, Timeout

from supplyguard.sbom.generator import Component

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
REQUEST_TIMEOUT_SECONDS = 10


@dataclass
class VulnMatch:
    """Represents a matched vulnerability from OSV.dev."""

    package: str
    version: str
    vuln_id: str
    severity: str
    summary: str
    fixed_version: str | None = None


def _http_post_with_retry(
    url: str, json_data: dict[str, Any], retries: int = 1
) -> requests.Response | None:
    """Post JSON data with explicit timeout and retry on timeout.

    Args:
        url: The endpoint URL.
        json_data: JSON payload.
        retries: Number of retry attempts on timeout.

    Returns:
        Response object or None if failed.
    """
    for attempt in range(retries + 1):
        try:
            return requests.post(url, json=json_data, timeout=REQUEST_TIMEOUT_SECONDS)
        except Timeout:
            if attempt < retries:
                logger.warning(f"Timeout connecting to {url}, retrying once...")
                continue
            logger.error(f"Timeout connecting to {url} after {retries + 1} attempts.")
        except RequestException as err:
            logger.error(f"HTTP request to {url} failed: {err}")
            break
    return None


def _http_get_with_retry(url: str, retries: int = 1) -> requests.Response | None:
    """Get URL with explicit timeout and retry on timeout.

    Args:
        url: The endpoint URL.
        retries: Number of retry attempts on timeout.

    Returns:
        Response object or None if failed.
    """
    for attempt in range(retries + 1):
        try:
            return requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
        except Timeout:
            if attempt < retries:
                logger.warning(f"Timeout requesting {url}, retrying once...")
                continue
            logger.error(f"Timeout requesting {url} after {retries + 1} attempts.")
        except RequestException as err:
            logger.error(f"HTTP GET {url} failed: {err}")
            break
    return None


def _extract_severity(vuln_data: dict[str, Any]) -> str:
    """Extract or normalize a severity rating from OSV vulnerability record.

    Args:
        vuln_data: Full OSV vulnerability JSON dictionary.

    Returns:
        Normalized severity string (CRITICAL, HIGH, MEDIUM, LOW).
    """
    severities = vuln_data.get("severity", [])
    for sev in severities:
        score_str = sev.get("score", "")
        if "CVSS:" in score_str:
            return _cvss_to_rating(score_str)

    # Check database_specific for severity hints
    db_spec = vuln_data.get("database_specific", {})
    if isinstance(db_spec, dict):
        raw_sev = db_spec.get("severity")
        if raw_sev and isinstance(raw_sev, str):
            return raw_sev.upper()

    return "MEDIUM"


def _cvss_to_rating(cvss_vector: str) -> str:
    """Map CVSS vector or score to qualitative severity rating."""
    upper_vec = cvss_vector.upper()
    if "CRITICAL" in upper_vec:
        return "CRITICAL"
    if "HIGH" in upper_vec and "LOW" not in upper_vec:
        return "HIGH"
    if "LOW" in upper_vec and "HIGH" not in upper_vec:
        return "LOW"

    # Analyze CVSS v3 vectors: AV:N (Network) + C:H/I:H/A:H -> CRITICAL (9.0+) or HIGH (7.5+)
    if "AV:N" in upper_vec and "C:H" in upper_vec and "I:H" in upper_vec:
        if "PR:N" in upper_vec and "UI:N" in upper_vec:
            return "CRITICAL"
        return "HIGH"
    if "C:H" in upper_vec or "I:H" in upper_vec or "A:H" in upper_vec:
        return "HIGH"
    return "MEDIUM"


def select_minimum_compatible_version(
    current_version: str, candidate_versions: list[str]
) -> str | None:
    """Select the minimum compatible fixed version prioritizing patch > minor > major bumps.

    Args:
        current_version: Current installed version string.
        candidate_versions: List of fixed version candidate strings.

    Returns:
        Best fixed version string, or None if no valid candidate found.
    """
    if not candidate_versions:
        return None

    try:
        from packaging.version import InvalidVersion, Version

        try:
            curr_v = Version(current_version)
        except InvalidVersion:
            return candidate_versions[0]

        parsed_candidates: list[tuple[Version, str]] = []
        for cand in candidate_versions:
            try:
                parsed_candidates.append((Version(cand), cand))
            except InvalidVersion:
                continue

        if not parsed_candidates:
            return candidate_versions[0]

        strictly_newer = [c for c in parsed_candidates if c[0] > curr_v]
        target_pool = strictly_newer if strictly_newer else parsed_candidates

        # 1. Same major, same minor (patch bump)
        same_major_same_minor = [
            c for c in target_pool
            if c[0].major == curr_v.major and c[0].minor == curr_v.minor
        ]
        if same_major_same_minor:
            same_major_same_minor.sort(key=lambda x: x[0])
            return same_major_same_minor[0][1]

        # 2. Same major, newer minor (minor bump)
        same_major_newer_minor = [
            c for c in target_pool
            if c[0].major == curr_v.major and c[0].minor > curr_v.minor
        ]
        if same_major_newer_minor:
            same_major_newer_minor.sort(key=lambda x: x[0])
            return same_major_newer_minor[0][1]

        # 3. Same major
        same_major = [c for c in target_pool if c[0].major == curr_v.major]
        if same_major:
            same_major.sort(key=lambda x: x[0])
            return same_major[0][1]

        # 4. Lowest newer version
        target_pool.sort(key=lambda x: x[0])
        return target_pool[0][1]

    except Exception:
        return candidate_versions[0]


def _extract_fixed_version(
    vuln_data: dict[str, Any], package_name: str, current_version: str | None = None
) -> str | None:
    """Find the minimum compatible fixed version from affected ranges in an OSV record.

    Args:
        vuln_data: Full OSV vulnerability JSON dictionary.
        package_name: Name of the package to match.
        current_version: Current installed version string, if available.

    Returns:
        Fixed version string if found, otherwise None.
    """
    affected_list = vuln_data.get("affected", [])
    candidates: list[str] = []
    for aff in affected_list:
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() == package_name.lower():
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed and str(fixed).strip() and str(fixed).strip() not in candidates:
                        candidates.append(str(fixed).strip())

    if not candidates:
        return None

    if not current_version:
        return candidates[0]

    return select_minimum_compatible_version(current_version, candidates)


def _fetch_vuln_detail(
    vuln_id: str, package: str, version: str
) -> VulnMatch:
    """Fetch full vulnerability record by ID and construct VulnMatch.

    Args:
        vuln_id: OSV vulnerability ID (e.g. GHSA-..., PYSEC-...).
        package: Component package name.
        version: Component installed version.

    Returns:
        Constructed VulnMatch instance.
    """
    detail_url = f"{OSV_VULN_URL}/{vuln_id}"
    resp = _http_get_with_retry(detail_url)
    if resp and resp.status_code == 200:
        data = resp.json()
        summary = data.get("summary") or data.get("details", "")[:200]
        severity = _extract_severity(data)
        fixed_version = _extract_fixed_version(data, package, current_version=version)
        return VulnMatch(
            package=package,
            version=version,
            vuln_id=vuln_id,
            severity=severity,
            summary=summary,
            fixed_version=fixed_version,
        )

    return VulnMatch(
        package=package,
        version=version,
        vuln_id=vuln_id,
        severity="MEDIUM",
        summary=f"Vulnerability {vuln_id} reported in OSV.dev",
        fixed_version=None,
    )


def batch_query(components: list[Component]) -> list[VulnMatch]:
    """Query OSV.dev in batches of 100 components for known vulnerabilities.

    Args:
        components: List of components to check against OSV.

    Returns:
        List of matched vulnerabilities.
    """
    if not components:
        return []

    # Filter components to those with meaningful versions
    valid_components = [
        c for c in components
        if c.version and c.version not in ("", "0.0.0", "None")
    ]
    if not valid_components:
        return []

    matches: list[VulnMatch] = []
    chunk_size = 100

    for i in range(0, len(valid_components), chunk_size):
        chunk = valid_components[i : i + chunk_size]
        queries = [
            {
                "package": {"name": comp.name, "ecosystem": "PyPI"},
                "version": comp.version,
            }
            for comp in chunk
        ]

        resp = _http_post_with_retry(OSV_BATCH_URL, {"queries": queries})
        if not resp or resp.status_code != 200:
            logger.warning(f"OSV batch query failed for chunk starting at {i}")
            continue

        results = resp.json().get("results", [])
        items_to_fetch: list[tuple[str, str, str]] = []
        for comp, res in zip(chunk, results):
            vulns = res.get("vulns", [])
            for vuln in vulns:
                vuln_id = vuln.get("id")
                if vuln_id:
                    items_to_fetch.append((vuln_id, comp.name, comp.version))

        if items_to_fetch:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(_fetch_vuln_detail, vid, pkg, ver)
                    for vid, pkg, ver in items_to_fetch
                ]
                for f in concurrent.futures.as_completed(futures):
                    try:
                        match = f.result()
                        matches.append(match)
                    except Exception as err:  # noqa: BLE001 - handle individual failed detail fetch gracefully
                        logger.warning(f"Error fetching vuln detail: {err}")

    return matches
