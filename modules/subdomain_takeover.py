"""
Phase 12: Subdomain Takeover Detection
Tools: subjack, subzy, nuclei takeover templates
"""

import os
import re
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, strip_ansi
from config import TOOLS


# Lines from subzy/subjack that are debug/status, NOT actual results
TAKEOVER_JUNK_PATTERNS = [
    r"^\[ \* \]",            # subzy status lines: [ * ] Loaded 76 fingerprints
    r"^\[ \d+ \]",           # subzy config lines: [ 10 ] Concurrent requests
    r"^\[ (Yes|No) \]",      # subzy config lines: [ No ] HTTPS by default
    r"^-+$",                 # separator lines: -----------------
    r"^\[ DISCUSSION \]",    # subzy reference links
    r"^\[ DOCUMENTATION \]", # subzy reference links
    r"^$",                   # empty lines
]
TAKEOVER_JUNK_RE = re.compile("|".join(TAKEOVER_JUNK_PATTERNS))


def _clean_takeover_line(line: str) -> str:
    """Clean and validate a takeover result line."""
    line = strip_ansi(line).strip()
    if not line:
        return ""
    if TAKEOVER_JUNK_RE.match(line):
        return ""
    return line


def _is_vulnerable(line: str) -> bool:
    """Check if a takeover line indicates actual vulnerability."""
    lower = line.lower()
    return "vulnerable" in lower and "not vulnerable" not in lower


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
        "-a",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = [_clean_takeover_line(l) for l in read_lines(output_file)]
    results = [l for l in results if l]
    write_lines(output_file, results)
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

    # subzy outputs to stdout - capture and clean
    raw_lines = []
    if stdout:
        raw_lines = stdout.split("\n")
    raw_lines.extend(read_lines(output_file))

    results = [_clean_takeover_line(l) for l in raw_lines]
    results = [l for l in results if l]
    write_lines(output_file, results)
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

    # Merge results - only clean lines
    all_results = []
    for f in [sj_file, sz_file, nt_file]:
        all_results.extend(read_lines(f))

    # Separate vulnerable from not-vulnerable for clean reporting
    vulnerable = []
    not_vulnerable = []
    other = []
    for line in all_results:
        line = _clean_takeover_line(line)
        if not line:
            continue
        if _is_vulnerable(line):
            vulnerable.append(line)
        elif "not vulnerable" in line.lower():
            not_vulnerable.append(line)
        else:
            other.append(line)

    # Write results: vulnerable first, then not-vulnerable
    takeover_file = os.path.join(scan_dir, "takeover_results.txt")
    final = []
    if vulnerable:
        final.append("=== VULNERABLE ===")
        final.extend(sorted(set(vulnerable)))
    if not_vulnerable:
        final.append("")
        final.append("=== NOT VULNERABLE ===")
        final.extend(sorted(set(not_vulnerable)))
    if other:
        final.append("")
        final.append("=== OTHER ===")
        final.extend(sorted(set(other)))

    write_lines(takeover_file, final)

    vuln_count = len(set(vulnerable))
    logger.found_count("VULNERABLE takeovers", vuln_count)
    logger.found_count("not vulnerable", len(set(not_vulnerable)))
    logger.phase_end(12, "Subdomain Takeover", vuln_count)
    return takeover_file
