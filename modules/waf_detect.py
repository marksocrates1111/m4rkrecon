"""
Phase 5: WAF Detection
Tools: wafw00f, whatwaf
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS


def run_wafw00f(target: str, output_file: str, logger) -> str:
    """Run wafw00f to detect WAF on target."""
    tool = TOOLS["wafw00f"]
    if not tool_exists(tool):
        logger.tool_not_found("wafw00f")
        return ""

    logger.info(f"Running wafw00f on {target}...")
    cmd = [tool, target, "-a", "-o", output_file]
    rc, stdout, stderr = run_command(cmd, timeout=60)

    if stdout:
        for line in stdout.split("\n"):
            if "is behind" in line.lower() or "waf" in line.lower():
                logger.info(f"  WAF: {line.strip()}")

    return stdout


def run_wafw00f_bulk(urls_file: str, output_file: str, logger) -> dict:
    """Run wafw00f on all live hosts."""
    tool = TOOLS["wafw00f"]
    if not tool_exists(tool):
        logger.tool_not_found("wafw00f")
        return {}

    logger.info("Running wafw00f on all live hosts...")
    cmd = [tool, "-i", urls_file, "-a", "-o", output_file]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = {}
    if stdout:
        for line in stdout.split("\n"):
            line = line.strip()
            if "is behind" in line.lower():
                results[line] = "detected"

    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 5: WAF Detection."""
    logger.phase_start(5, "WAF Detection", "wafw00f")

    output_file = os.path.join(scan_dir, "waf_results.txt")
    urls_file = os.path.join(scan_dir, "live_urls.txt")

    # First check main domain
    main_target = f"https://{domain}"
    run_wafw00f(main_target, output_file, logger)

    # Then bulk check if we have live URLs
    if os.path.isfile(urls_file):
        bulk_file = os.path.join(scan_dir, "waf_bulk.txt")
        results = run_wafw00f_bulk(urls_file, bulk_file, logger)
        logger.found_count("WAF detections", len(results))
    else:
        logger.info("No live URLs file - checked main domain only")

    logger.phase_end(5, "WAF Detection", len(read_lines(output_file)))
    return output_file
