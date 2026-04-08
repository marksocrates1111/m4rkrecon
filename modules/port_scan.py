"""
Phase 6: Port Scanning
Tools: naabu (primary), nmap (fallback)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, parse_jsonl
from config import TOOLS, PORT_RATE


def run_naabu(input_file: str, output_file: str, json_file: str, logger) -> list[str]:
    """Run naabu for fast port scanning."""
    tool = TOOLS["naabu"]
    if not tool_exists(tool):
        logger.tool_not_found("naabu")
        return []

    logger.info("Running naabu (top 1000 ports)...")
    cmd = [
        tool,
        "-list", input_file,
        "-o", output_file,
        "-json", "-output", json_file,
        "-top-ports", "1000",
        "-silent",
        "-rate", str(PORT_RATE),
        "-c", "50",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    if rc != 0 and stderr:
        logger.warning(f"naabu: {stderr[:200]}")

    results = read_lines(output_file)
    logger.found_count("open ports", len(results))
    return results


def run_nmap(input_file: str, output_file: str, logger) -> list[str]:
    """Run nmap as fallback for port scanning."""
    tool = TOOLS["nmap"]
    if not tool_exists(tool):
        logger.tool_not_found("nmap")
        return []

    logger.info("Running nmap (top 1000 ports)...")
    cmd = [
        tool,
        "-iL", input_file,
        "-oN", output_file,
        "--top-ports", "1000",
        "-T4",
        "--open",
        "-sV",
        "--min-rate", "1000",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=900)

    if rc != 0 and stderr:
        logger.warning(f"nmap: {stderr[:200]}")

    results = read_lines(output_file)
    logger.found_count("nmap results", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 6: Port Scanning."""
    logger.phase_start(6, "Port Scanning", "naabu / nmap")

    subdomains_file = os.path.join(scan_dir, "subdomains.txt")
    if not os.path.isfile(subdomains_file):
        logger.warning("No subdomains file - skipping port scan")
        logger.phase_end(6, "Port Scanning", 0)
        return ""

    ports_file = os.path.join(scan_dir, "ports.txt")
    json_file = os.path.join(scan_dir, "ports.json")

    # Try naabu first, fallback to nmap
    results = run_naabu(subdomains_file, ports_file, json_file, logger)
    if not results:
        nmap_file = os.path.join(scan_dir, "nmap_results.txt")
        run_nmap(subdomains_file, nmap_file, logger)
        ports_file = nmap_file

    logger.phase_end(6, "Port Scanning", len(read_lines(ports_file)))
    return ports_file
