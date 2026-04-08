"""
Phase 3: DNS Resolution
Tools: dnsx
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def run_dnsx(input_file: str, output_file: str, logger) -> list[str]:
    """Run dnsx to resolve subdomains and get DNS records."""
    tool = TOOLS["dnsx"]
    if not tool_exists(tool):
        logger.tool_not_found("dnsx")
        return []

    logger.info("Running dnsx for DNS resolution...")
    cmd = [
        tool,
        "-l", input_file,
        "-o", output_file,
        "-silent",
        "-a", "-aaaa", "-cname", "-mx", "-ns",
        "-resp",
        "-t", str(THREADS),
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    if rc != 0 and stderr:
        logger.warning(f"dnsx: {stderr[:200]}")

    results = read_lines(output_file)
    logger.found_count("resolved domains", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 3: DNS Resolution."""
    logger.phase_start(3, "DNS Resolution", "dnsx")

    subdomains_file = os.path.join(scan_dir, "subdomains.txt")
    if not os.path.isfile(subdomains_file):
        logger.warning("No subdomains file found - skipping DNS resolution")
        logger.phase_end(3, "DNS Resolution", 0)
        return ""

    resolved_file = os.path.join(scan_dir, "resolved.txt")
    run_dnsx(subdomains_file, resolved_file, logger)

    logger.phase_end(3, "DNS Resolution", len(read_lines(resolved_file)))
    return resolved_file
