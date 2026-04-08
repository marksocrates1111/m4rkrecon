"""
Phase 17: SSRF Detection
Tools: nuclei SSRF templates (primary), built-in checker (fallback)
"""

import os
import requests
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS

SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "file", "page", "feed",
    "host", "site", "html", "data", "reference", "ref", "img", "src",
    "load", "target", "proxy", "port", "to", "out", "view", "dir",
    "show", "navigation", "open", "domain", "callback", "return",
    "fetch", "next", "content", "document", "folder", "val",
]


def run_nuclei_ssrf(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei with SSRF-specific templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        logger.tool_not_found("nuclei")
        return []

    logger.info("Running nuclei SSRF templates...")
    cmd = [
        tool,
        "-l", input_file,
        "-t", "http/vulnerabilities/",
        "-tags", "ssrf",
        "-o", output_file,
        "-silent",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("SSRF vulnerabilities (nuclei)", len(results))
    return results


def check_ssrf_params(urls_file: str, output_file: str, logger) -> list[str]:
    """Check for potential SSRF in URL parameters."""
    logger.info("Checking for SSRF-susceptible parameters...")
    urls = read_lines(urls_file)
    findings = []

    for url in urls:
        url_lower = url.lower()
        for param in SSRF_PARAMS:
            if f"{param}=" in url_lower:
                # Check if param value looks like a URL/path
                try:
                    parts = url.split(f"{param}=", 1)
                    if len(parts) > 1:
                        val = parts[1].split("&")[0]
                        if val.startswith(("http", "/", "file:", "ftp:")):
                            findings.append(f"[SSRF-CANDIDATE] {url} (param: {param})")
                except Exception:
                    continue

    unique = list(set(findings))[:100]
    write_lines(output_file, unique)
    logger.found_count("SSRF-susceptible URLs", len(unique))
    return unique


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 17: SSRF Detection."""
    logger.phase_start(17, "SSRF Detection", "nuclei + param analysis")

    urls_file = os.path.join(scan_dir, "all_urls.txt")
    if not os.path.isfile(urls_file):
        urls_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(urls_file):
        logger.warning("No URLs - skipping SSRF detection")
        logger.phase_end(17, "SSRF Detection", 0)
        return ""

    ssrf_file = os.path.join(scan_dir, "ssrf_results.txt")

    # Run nuclei SSRF templates
    nuclei_file = os.path.join(scan_dir, "ssrf_nuclei.txt")
    run_nuclei_ssrf(urls_file, nuclei_file, logger)

    # Also check for SSRF-susceptible params
    params_file = os.path.join(scan_dir, "ssrf_candidates.txt")
    check_ssrf_params(urls_file, params_file, logger)

    # Merge results
    all_findings = read_lines(nuclei_file) + read_lines(params_file)
    write_lines(ssrf_file, sorted(set(all_findings)))

    logger.phase_end(17, "SSRF Detection", len(all_findings))
    return ssrf_file
