"""
Phase 13: XSS Scanning
Tools: dalfox (primary), kxss (pre-filter)
Uses urls_xss.txt from Phase 10 categorization.
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
    ]
    rc, stdout, stderr = run_command(cmd, timeout=900)

    results = read_lines(output_file)
    logger.found_count("XSS vulnerabilities", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 13: XSS Scanning."""
    logger.phase_start(13, "XSS Scanning", "dalfox + kxss")

    # Priority: categorized xss URLs > all parameterized URLs
    xss_urls_file = os.path.join(scan_dir, "urls_xss.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(xss_urls_file) and read_lines(xss_urls_file):
        source_file = xss_urls_file
        logger.info(f"Using {len(read_lines(source_file))} XSS-categorized URLs")
    elif os.path.isfile(params_file) and read_lines(params_file):
        source_file = params_file
        logger.info(f"Using {len(read_lines(source_file))} parameterized URLs")
    else:
        logger.warning("No parameterized URLs found - skipping XSS scan")
        logger.phase_end(13, "XSS Scan", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase13_xss")
    os.makedirs(phase_dir, exist_ok=True)

    # Cap at 500 URLs for speed
    urls = read_lines(source_file)[:500]
    scan_file = os.path.join(phase_dir, "xss_targets.txt")
    write_lines(scan_file, urls)
    logger.info(f"Testing {len(urls)} URLs for XSS...")

    # Pre-filter with kxss
    kxss_file = os.path.join(phase_dir, "kxss_reflected.txt")
    reflected = run_kxss(scan_file, kxss_file, logger)
    scan_input = kxss_file if reflected else scan_file

    # Run dalfox
    xss_file = os.path.join(scan_dir, "xss_results.txt")
    run_dalfox(scan_input, xss_file, logger)

    logger.phase_end(13, "XSS Scan", len(read_lines(xss_file)))
    return xss_file
