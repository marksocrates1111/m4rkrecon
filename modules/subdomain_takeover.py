"""
Phase 12: Subdomain Takeover Detection
Tools: subjack, subzy, nuclei takeover templates
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, merge_files
from config import TOOLS


def run_subjack(input_file: str, output_file: str, logger) -> list[str]:
    """Run subjack for subdomain takeover detection."""
    tool = TOOLS["subjack"]
    if not tool_exists(tool):
        logger.tool_not_found("subjack")
        return []

    logger.info("Running subjack...")
    cmd = [
        tool,
        "-w", input_file,
        "-o", output_file,
        "-t", "100",
        "-timeout", "30",
        "-ssl",
        "-a",  # check all CNAME results
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("potential takeovers (subjack)", len(results))
    return results


def run_subzy(input_file: str, output_file: str, logger) -> list[str]:
    """Run subzy for subdomain takeover detection."""
    tool = TOOLS["subzy"]
    if not tool_exists(tool):
        logger.tool_not_found("subzy")
        return []

    logger.info("Running subzy...")
    cmd = [tool, "run", "--targets", input_file, "--output", output_file]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    if stdout:
        # subzy outputs to stdout
        write_lines(output_file, [l for l in stdout.split("\n") if l.strip()])

    results = read_lines(output_file)
    logger.found_count("potential takeovers (subzy)", len(results))
    return results


def run_nuclei_takeover(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei with takeover templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        logger.tool_not_found("nuclei")
        return []

    logger.info("Running nuclei takeover templates...")
    cmd = [
        tool,
        "-l", input_file,
        "-t", "http/takeovers/",
        "-o", output_file,
        "-silent",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("potential takeovers (nuclei)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 12: Subdomain Takeover Detection."""
    logger.phase_start(12, "Subdomain Takeover Detection", "subjack + subzy + nuclei")

    subdomains_file = os.path.join(scan_dir, "subdomains.txt")
    if not os.path.isfile(subdomains_file):
        logger.warning("No subdomains file - skipping takeover detection")
        logger.phase_end(12, "Subdomain Takeover", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase12_takeover")
    os.makedirs(phase_dir, exist_ok=True)

    sj_file = os.path.join(phase_dir, "subjack.txt")
    sz_file = os.path.join(phase_dir, "subzy.txt")
    nt_file = os.path.join(phase_dir, "nuclei_takeover.txt")

    run_subjack(subdomains_file, sj_file, logger)
    run_subzy(subdomains_file, sz_file, logger)
    run_nuclei_takeover(subdomains_file, nt_file, logger)

    # Merge results
    takeover_file = os.path.join(scan_dir, "takeover_results.txt")
    merged = merge_files([sj_file, sz_file, nt_file], takeover_file)

    logger.phase_end(12, "Subdomain Takeover", len(merged))
    return takeover_file
