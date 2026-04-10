"""
Phase 22: CRLF Injection Detection
Fixed: Actually verifies header injection, not just URL reflection in Location.
"""

import os
import requests as req
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS

CRLF_PAYLOADS = [
    ("/%0d%0aX-M4rk-Injected:true", "x-m4rk-injected"),
    ("/%0aX-M4rk-Injected:true", "x-m4rk-injected"),
    ("/%0dX-M4rk-Injected:true", "x-m4rk-injected"),
    ("/%23%0dX-M4rk-Injected:true", "x-m4rk-injected"),
    ("/%E5%98%8A%E5%98%8DX-M4rk-Injected:true", "x-m4rk-injected"),
]


def run_crlf_check(urls_file: str, output_file: str, logger) -> list[str]:
    """Check for CRLF injection by verifying the injected header appears
    as a SEPARATE response header, not just reflected inside a Location URL."""
    urls = read_lines(urls_file)[:100]
    if not urls:
        return []

    logger.info(f"Testing {len(urls)} URLs for CRLF injection...")
    findings = []

    for url in urls:
        for payload_path, header_name in CRLF_PAYLOADS:
            try:
                test_url = url.rstrip("/") + payload_path
                resp = req.get(test_url, timeout=5, verify=False, allow_redirects=False)

                # Check if our header appears as a SEPARATE response header
                # NOT just inside a Location URL (which is a false positive)
                for h_name, h_val in resp.headers.items():
                    h_name_lower = h_name.lower()

                    # Skip Location header - payload in Location URL is NOT CRLF
                    if h_name_lower == "location":
                        continue

                    # Our injected header must appear as its own header
                    if h_name_lower == header_name:
                        findings.append(f"[CRLF] {url} - Injected header: {h_name}: {h_val}")
                        logger.success(f"  CRLF confirmed: {url[:80]}")
                        break

                    # Also check if our marker appears in Set-Cookie or other headers
                    if "m4rk-injected" in h_val.lower() and h_name_lower != "location":
                        findings.append(f"[CRLF] {url} - Reflected in: {h_name}")
                        logger.success(f"  CRLF confirmed: {url[:80]}")
                        break

                if findings and findings[-1].startswith(f"[CRLF] {url}"):
                    break  # Found for this URL, move to next

            except Exception:
                continue

    unique = sorted(set(findings))
    write_lines(output_file, unique)
    logger.found_count("CRLF injections (verified)", len(unique))
    return unique


def run_nuclei_crlf(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei CRLF templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei CRLF templates...")
    cmd = [tool, "-l", input_file, "-tags", "crlf", "-o", output_file, "-silent", "-rl", "30"]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("CRLF (nuclei)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 22: CRLF Injection Detection."""
    logger.phase_start(22, "CRLF Injection Detection", "verified header injection + nuclei")

    live_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(live_file) or not read_lines(live_file):
        logger.warning("No live URLs - skipping CRLF")
        logger.phase_end(22, "CRLF Detection", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase22_crlf")
    os.makedirs(phase_dir, exist_ok=True)

    all_results = []

    crlf_file = os.path.join(phase_dir, "crlf_check.txt")
    crlf_results = run_crlf_check(live_file, crlf_file, logger)
    all_results.extend(crlf_results)

    nuclei_file = os.path.join(phase_dir, "nuclei_crlf.txt")
    nuclei_results = run_nuclei_crlf(live_file, nuclei_file, logger)
    all_results.extend(nuclei_results)

    crlf_results_file = os.path.join(scan_dir, "crlf_results.txt")
    write_lines(crlf_results_file, sorted(set(all_results)))

    logger.phase_end(22, "CRLF Detection", len(set(all_results)))
    return crlf_results_file
