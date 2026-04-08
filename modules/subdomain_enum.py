"""
Phase 1: Subdomain Enumeration
Tools: subfinder, amass, assetfinder, crt.sh API
"""

import os
import json
import requests
from core.runner import run_command, tool_exists
from core.utils import write_lines, merge_files, read_lines
from config import TOOLS, THREADS


def run_subfinder(domain: str, output_file: str, logger) -> list[str]:
    """Run subfinder for passive subdomain enumeration."""
    tool = TOOLS["subfinder"]
    if not tool_exists(tool):
        logger.tool_not_found("subfinder")
        return []

    logger.info("Running subfinder...")
    cmd = [tool, "-d", domain, "-all", "-silent", "-o", output_file, "-t", str(THREADS)]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    if rc != 0 and stderr:
        logger.warning(f"subfinder: {stderr[:200]}")

    results = read_lines(output_file)
    logger.found_count("subdomains (subfinder)", len(results))
    return results


def run_amass(domain: str, output_file: str, logger) -> list[str]:
    """Run amass for passive subdomain enumeration."""
    tool = TOOLS["amass"]
    if not tool_exists(tool):
        logger.tool_not_found("amass")
        return []

    logger.info("Running amass (passive)...")
    cmd = [tool, "enum", "-passive", "-d", domain, "-o", output_file]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    if rc != 0 and stderr:
        logger.warning(f"amass: {stderr[:200]}")

    results = read_lines(output_file)
    logger.found_count("subdomains (amass)", len(results))
    return results


def run_assetfinder(domain: str, output_file: str, logger) -> list[str]:
    """Run assetfinder for subdomain discovery."""
    tool = TOOLS["assetfinder"]
    if not tool_exists(tool):
        logger.tool_not_found("assetfinder")
        return []

    logger.info("Running assetfinder...")
    cmd = [tool, "--subs-only", domain]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=120)

    results = read_lines(output_file)
    logger.found_count("subdomains (assetfinder)", len(results))
    return results


def run_crtsh(domain: str, output_file: str, logger) -> list[str]:
    """Query crt.sh certificate transparency logs."""
    logger.info("Querying crt.sh...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            logger.warning(f"crt.sh returned status {resp.status_code}")
            return []

        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and "*" not in sub and sub.endswith(domain):
                    subdomains.add(sub)

        results = sorted(subdomains)
        write_lines(output_file, results)
        logger.found_count("subdomains (crt.sh)", len(results))
        return results

    except Exception as e:
        logger.warning(f"crt.sh error: {e}")
        return []


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 1: Subdomain Enumeration. Returns path to merged results."""
    logger.phase_start(1, "Subdomain Enumeration", "subfinder + amass + assetfinder + crt.sh")

    phase_dir = os.path.join(scan_dir, "phase1_subdomains")
    os.makedirs(phase_dir, exist_ok=True)

    # Run all tools
    sf_file = os.path.join(phase_dir, "subfinder.txt")
    am_file = os.path.join(phase_dir, "amass.txt")
    af_file = os.path.join(phase_dir, "assetfinder.txt")
    ct_file = os.path.join(phase_dir, "crtsh.txt")

    run_subfinder(domain, sf_file, logger)
    run_amass(domain, am_file, logger)
    run_assetfinder(domain, af_file, logger)
    run_crtsh(domain, ct_file, logger)

    # Merge and dedup
    merged_file = os.path.join(scan_dir, "subdomains.txt")
    all_subs = merge_files([sf_file, am_file, af_file, ct_file], merged_file)

    logger.phase_end(1, "Subdomain Enumeration", len(all_subs))
    return merged_file
