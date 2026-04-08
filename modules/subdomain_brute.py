"""
Phase 2: Subdomain Bruteforce
Tools: shuffledns, puredns
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, merge_files
from config import TOOLS, WORDLISTS, DNS_RESOLVERS


def run_shuffledns(domain: str, output_file: str, logger) -> list[str]:
    """Run shuffledns for DNS bruteforce."""
    tool = TOOLS["shuffledns"]
    if not tool_exists(tool):
        logger.tool_not_found("shuffledns")
        return []

    wordlist = WORDLISTS.get("subdomains", "")
    if not os.path.isfile(wordlist):
        logger.warning("Subdomain wordlist not found - skipping bruteforce")
        return []

    logger.info("Running shuffledns bruteforce...")
    cmd = [tool, "-d", domain, "-w", wordlist, "-o", output_file, "-silent"]

    # Add resolvers if available
    if os.path.isfile(DNS_RESOLVERS):
        cmd.extend(["-r", DNS_RESOLVERS])

    rc, stdout, stderr = run_command(cmd, timeout=600)

    if rc != 0 and stderr:
        logger.warning(f"shuffledns: {stderr[:200]}")

    results = read_lines(output_file)
    logger.found_count("subdomains (bruteforce)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 2: Subdomain Bruteforce."""
    logger.phase_start(2, "Subdomain Bruteforce", "shuffledns")

    phase_dir = os.path.join(scan_dir, "phase2_brute")
    os.makedirs(phase_dir, exist_ok=True)

    brute_file = os.path.join(phase_dir, "shuffledns.txt")
    run_shuffledns(domain, brute_file, logger)

    # Merge with existing subdomains
    existing_subs = os.path.join(scan_dir, "subdomains.txt")
    merged = merge_files([existing_subs, brute_file], existing_subs)

    logger.phase_end(2, "Subdomain Bruteforce", len(merged))
    return existing_subs
