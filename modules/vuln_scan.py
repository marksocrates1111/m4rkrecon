"""
Phase 11: Vulnerability Scanning
Tools: nuclei (full template library)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, parse_jsonl, write_lines
from config import TOOLS, THREADS, RATE_LIMIT, NUCLEI_SEVERITY, NUCLEI_TEMPLATES_EXCLUDE


def run_nuclei(input_file: str, output_file: str, json_file: str, logger, severity: str = "") -> list[str]:
    """Run nuclei vulnerability scanner."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        logger.tool_not_found("nuclei")
        return []

    logger.info("Running nuclei vulnerability scanner...")

    # Run with JSONL output to the json_file, plain text to output_file
    cmd = [
        tool,
        "-l", input_file,
        "-o", output_file,
        "-j",
        "-silent",
        "-c", str(min(THREADS, 25)),
        "-rl", str(RATE_LIMIT),
        "-timeout", "10",
        "-retries", "2",
        "-severity", severity or NUCLEI_SEVERITY,
    ]

    # Exclude template categories
    for exclude in NUCLEI_TEMPLATES_EXCLUDE:
        cmd.extend(["-etags", exclude])

    rc, stdout, stderr = run_command(cmd, timeout=1800)

    if rc != 0 and stderr:
        errors = [l for l in stderr.split("\n") if "error" in l.lower()]
        if errors:
            logger.warning(f"nuclei errors: {errors[0][:200]}")

    # The -j flag makes -o write JSONL. Copy it as the json file too.
    results = read_lines(output_file)
    if results:
        write_lines(json_file, results)

    logger.found_count("nuclei findings", len(results))
    return results


def parse_nuclei_results(json_file: str) -> dict:
    """Parse nuclei JSON results into severity categories."""
    entries = parse_jsonl(json_file)
    severity_map = {"info": [], "low": [], "medium": [], "high": [], "critical": []}

    for entry in entries:
        try:
            info = entry.get("info", {})
            if not isinstance(info, dict):
                info = {}
            sev = info.get("severity", "info")
            if not isinstance(sev, str):
                sev = "info"
            sev = sev.lower()
            finding = {
                "template": entry.get("template-id", "unknown"),
                "name": info.get("name", ""),
                "severity": sev,
                "host": entry.get("host", ""),
                "matched_at": entry.get("matched-at", ""),
                "type": entry.get("type", ""),
                "description": info.get("description", ""),
            }
            if sev in severity_map:
                severity_map[sev].append(finding)
            else:
                severity_map["info"].append(finding)
        except Exception:
            continue

    return severity_map


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 11: Vulnerability Scanning."""
    logger.phase_start(11, "Vulnerability Scanning", "nuclei")

    # Use live URLs if available, else subdomains
    input_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(input_file):
        input_file = os.path.join(scan_dir, "subdomains.txt")
    if not os.path.isfile(input_file):
        logger.warning("No targets file - skipping nuclei scan")
        logger.phase_end(11, "Vulnerability Scan", 0)
        return ""

    vulns_file = os.path.join(scan_dir, "nuclei_results.txt")
    json_file = os.path.join(scan_dir, "nuclei_results.json")

    results = run_nuclei(input_file, vulns_file, json_file, logger)

    # Parse and display severity breakdown
    if os.path.isfile(json_file):
        severity_map = parse_nuclei_results(json_file)
        for sev, findings in severity_map.items():
            if findings:
                logger.found_count(f"{sev} severity vulns", len(findings))

    logger.phase_end(11, "Vulnerability Scan", len(results))
    return vulns_file
