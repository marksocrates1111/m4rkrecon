"""
Phase 18: SSL/TLS Analysis
Tools: tlsx (primary), sslscan (fallback)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, parse_jsonl
from config import TOOLS


def run_tlsx(input_file: str, output_file: str, json_file: str, logger) -> list[str]:
    """Run tlsx for TLS analysis."""
    tool = TOOLS["tlsx"]
    if not tool_exists(tool):
        logger.tool_not_found("tlsx")
        return []

    logger.info("Running tlsx...")
    cmd = [
        tool,
        "-l", input_file,
        "-o", output_file,
        "-json", "-output", json_file,
        "-silent",
        "-expired",          # show expired certs
        "-mismatched",       # show mismatched certs
        "-self-signed",      # show self-signed certs
        "-tls-version",      # show TLS version
        "-cipher",           # show cipher suite
        "-san",              # show SANs
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("TLS results", len(results))
    return results


def run_sslscan(domain: str, output_file: str, logger) -> str:
    """Run sslscan on main domain."""
    tool = TOOLS["sslscan"]
    if not tool_exists(tool):
        logger.tool_not_found("sslscan")
        return ""

    logger.info(f"Running sslscan on {domain}...")
    cmd = [tool, "--no-colour", domain]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=60)
    return stdout


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 18: SSL/TLS Analysis."""
    logger.phase_start(18, "SSL/TLS Analysis", "tlsx / sslscan")

    subdomains_file = os.path.join(scan_dir, "subdomains.txt")
    ssl_file = os.path.join(scan_dir, "ssl_results.txt")
    json_file = os.path.join(scan_dir, "ssl_results.json")

    if os.path.isfile(subdomains_file):
        run_tlsx(subdomains_file, ssl_file, json_file, logger)
    else:
        # At minimum scan the main domain
        run_sslscan(domain, ssl_file, logger)

    # Also run sslscan on main domain for detailed output
    sslscan_file = os.path.join(scan_dir, "sslscan_main.txt")
    run_sslscan(domain, sslscan_file, logger)

    logger.phase_end(18, "SSL/TLS Analysis", len(read_lines(ssl_file)))
    return ssl_file
