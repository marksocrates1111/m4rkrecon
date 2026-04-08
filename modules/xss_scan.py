"""
Phase 13: XSS Scanning
Tools: dalfox (primary), kxss (pre-filter)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def run_kxss(input_file: str, output_file: str, logger) -> list[str]:
    """Run kxss to pre-filter URLs with reflected parameters."""
    tool = TOOLS["kxss"]
    if not tool_exists(tool):
        logger.tool_not_found("kxss")
        return []

    logger.info("Running kxss pre-filter...")
    urls = read_lines(input_file)
    stdin_data = "\n".join(urls)

    cmd = [tool]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=300, stdin_data=stdin_data)

    results = read_lines(output_file)
    logger.found_count("reflected parameter URLs", len(results))
    return results


def run_dalfox(input_file: str, output_file: str, logger) -> list[str]:
    """Run dalfox XSS scanner."""
    tool = TOOLS["dalfox"]
    if not tool_exists(tool):
        logger.tool_not_found("dalfox")
        return []

    logger.info("Running dalfox XSS scanner...")
    cmd = [
        tool,
        "file", input_file,
        "-o", output_file,
        "--silence",
        "--worker", str(min(THREADS, 20)),
        "--timeout", "10",
        "--skip-bav",       # skip BAV analysis for speed
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("XSS vulnerabilities", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 13: XSS Scanning."""
    logger.phase_start(13, "XSS Scanning", "dalfox + kxss")

    # Use parameterized URLs or all URLs
    urls_file = os.path.join(scan_dir, "parameters.txt")
    if not os.path.isfile(urls_file) or len(read_lines(urls_file)) == 0:
        urls_file = os.path.join(scan_dir, "all_urls.txt")
    if not os.path.isfile(urls_file):
        logger.warning("No URLs found - skipping XSS scan")
        logger.phase_end(13, "XSS Scan", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase13_xss")
    os.makedirs(phase_dir, exist_ok=True)

    # Pre-filter with kxss if available
    kxss_file = os.path.join(phase_dir, "kxss_reflected.txt")
    reflected = run_kxss(urls_file, kxss_file, logger)

    # Use reflected URLs if available, otherwise use all URLs
    scan_input = kxss_file if reflected else urls_file

    # Run dalfox
    xss_file = os.path.join(scan_dir, "xss_results.txt")
    run_dalfox(scan_input, xss_file, logger)

    logger.phase_end(13, "XSS Scan", len(read_lines(xss_file)))
    return xss_file
