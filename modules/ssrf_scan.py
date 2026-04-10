"""
Phase 17: SSRF Detection
Fixed: Validates SSRF by comparing response differences, not just HTTP 200.
Uses baseline comparison to reduce false positives.
"""

import os
import requests as req
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS

# Params that commonly accept URLs (real SSRF vectors)
SSRF_PARAMS = ["url", "uri", "src", "href", "redirect", "feed", "load",
               "fetch", "proxy", "img", "image", "callback"]

# Params that are almost always just pagination/tracking (NOT SSRF)
FALSE_POSITIVE_PARAMS = ["ref", "page", "next", "return_to", "returnTo",
                         "goto", "continue", "q", "query", "search",
                         "sort", "order", "limit", "offset", "per_page",
                         "locale", "lang", "brand_id", "role", "state",
                         "scope", "response_type", "client_id"]


def _is_likely_ssrf_param(url: str) -> bool:
    """Check if URL has params that could actually be SSRF vectors,
    filtering out pagination/tracking params."""
    url_lower = url.lower()
    # Must have a real SSRF-like param
    has_ssrf_param = any(f"{p}=" in url_lower for p in SSRF_PARAMS)
    if has_ssrf_param:
        return True
    # If only has false-positive params, skip
    has_only_fp = all(
        any(f"{fp}=" in part.lower() for fp in FALSE_POSITIVE_PARAMS)
        for part in url.split("?", 1)[1].split("&") if "=" in part
    ) if "?" in url else False
    return not has_only_fp


def run_ssrf_baseline_check(input_file: str, output_file: str, logger) -> list[str]:
    """SSRF detection with baseline comparison.
    Compares response with normal value vs SSRF payload to detect actual
    server-side request behavior (size diff, timing diff, error diff)."""
    urls = read_lines(input_file)
    # Filter to only URLs with actual SSRF-likely params
    ssrf_urls = [u for u in urls if _is_likely_ssrf_param(u)][:100]

    if not ssrf_urls:
        logger.info("No SSRF-likely parameters found after filtering")
        return []

    logger.info(f"Testing {len(ssrf_urls)} URLs with SSRF-likely params...")
    findings = []

    for url in ssrf_urls:
        try:
            # Baseline: normal request
            resp_normal = req.get(url, timeout=5, verify=False, allow_redirects=True)
            normal_size = len(resp_normal.text)
            normal_status = resp_normal.status_code

            # Test: replace param values with SSRF payload
            # Try http://127.0.0.1:80
            test_url = url
            for param in SSRF_PARAMS:
                if f"{param}=" in test_url.lower():
                    import re
                    test_url = re.sub(
                        f"({param})=[^&]*",
                        f"\\1=http://127.0.0.1:80",
                        test_url,
                        flags=re.IGNORECASE,
                    )

            resp_test = req.get(test_url, timeout=5, verify=False, allow_redirects=True)
            test_size = len(resp_test.text)
            test_status = resp_test.status_code

            # Compare: significant difference indicates server processed the URL
            size_diff = abs(test_size - normal_size)
            size_ratio = size_diff / max(normal_size, 1)

            if (
                # Response size changed significantly (>20%)
                (size_ratio > 0.2 and size_diff > 100)
                # OR status code changed
                or (test_status != normal_status)
                # OR response contains SSRF indicators
                or any(m in resp_test.text.lower() for m in [
                    "connection refused", "could not resolve",
                    "<!doctype html>", "localhost", "127.0.0.1",
                    "internal server error",
                ])
            ):
                findings.append(
                    f"[SSRF] {url} - status:{normal_status}->{test_status} "
                    f"size:{normal_size}->{test_size} ({size_ratio:.0%} diff)"
                )
                logger.success(f"  SSRF candidate: {url[:80]}")

        except Exception:
            continue

    unique = sorted(set(findings))
    write_lines(output_file, unique)
    logger.found_count("SSRF candidates (verified)", len(unique))
    return unique


def run_nuclei_ssrf(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei with SSRF templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei SSRF templates...")
    cmd = [tool, "-l", input_file, "-tags", "ssrf", "-o", output_file, "-silent", "-rl", "30"]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("SSRF (nuclei)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 17: SSRF Detection - with baseline validation."""
    logger.phase_start(17, "SSRF Detection", "baseline comparison + nuclei")

    ssrf_file = os.path.join(scan_dir, "urls_ssrf.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(ssrf_file) and read_lines(ssrf_file):
        source = ssrf_file
    elif os.path.isfile(params_file) and read_lines(params_file):
        source = params_file
    else:
        logger.warning("No parameterized URLs - skipping SSRF")
        logger.phase_end(17, "SSRF Detection", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase17_ssrf")
    os.makedirs(phase_dir, exist_ok=True)

    all_ssrf = []

    # Technique 1: Baseline comparison SSRF check
    baseline_file = os.path.join(phase_dir, "baseline_ssrf.txt")
    baseline_results = run_ssrf_baseline_check(source, baseline_file, logger)
    all_ssrf.extend(baseline_results)

    # Technique 2: nuclei SSRF templates
    nuclei_file = os.path.join(phase_dir, "nuclei_ssrf.txt")
    nuclei_results = run_nuclei_ssrf(source, nuclei_file, logger)
    all_ssrf.extend(nuclei_results)

    ssrf_results = os.path.join(scan_dir, "ssrf_results.txt")
    write_lines(ssrf_results, sorted(set(all_ssrf)))

    logger.phase_end(17, "SSRF Detection", len(set(all_ssrf)))
    return ssrf_results
