"""
Phase 12: Subdomain Takeover Detection
Tools: subjack, subzy, nuclei takeover templates
"""

import os
import re
import json
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, strip_ansi
from config import TOOLS


def _parse_subzy_output(raw_file: str, stdout: str) -> list[str]:
    """Parse subzy output which can be JSON or text format."""
    results = []

    # Try to parse subzy JSON output (newer versions output JSON)
    for source in [stdout, None]:
        content = source
        if content is None:
            if os.path.isfile(raw_file):
                with open(raw_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            else:
                continue
        if not content or not content.strip():
            continue
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    sub = entry.get("subdomain", "")
                    status = entry.get("status", "")
                    engine = entry.get("engine", "")
                    if not sub:
                        continue
                    if status == "vulnerable" and engine:
                        results.append(f"[ VULNERABLE ]  -  {sub}  [ {engine} ]")
                    elif "not vulnerable" in str(status).lower():
                        results.append(f"[ NOT VULNERABLE ]  -  {sub}")
                return results
        except (json.JSONDecodeError, TypeError):
            pass

    # Fallback: parse text output line by line
    lines = []
    if stdout:
        lines.extend(stdout.split("\n"))
    lines.extend(read_lines(raw_file))

    for line in lines:
        line = strip_ansi(line).strip()
        if not line:
            continue
        # Only keep actual result lines
        if line.startswith("[ VULNERABLE ]") or line.startswith("[ NOT VULNERABLE ]"):
            results.append(line)
        elif line.startswith("[GEMFURY]") or line.startswith("[NETLIFY]") or line.startswith("[CARGO"):
            # subzy shorthand: [GEMFURY] domain.com
            parts = line.split("]", 1)
            if len(parts) == 2:
                engine = parts[0].strip("[").strip()
                sub = parts[1].strip()
                results.append(f"[ VULNERABLE ]  -  {sub}  [ {engine} ]")
        elif line.startswith("[Not Vulnerable]"):
            sub = line.replace("[Not Vulnerable]", "").strip()
            results.append(f"[ NOT VULNERABLE ]  -  {sub}")

    return results


def run_subjack(input_file: str, output_file: str, logger) -> list[str]:
    """Run subjack for subdomain takeover detection."""
    tool = TOOLS["subjack"]
    if not tool_exists(tool):
        logger.tool_not_found("subjack")
        return []

    logger.info("Running subjack...")
    cmd = [tool, "-w", input_file, "-o", output_file, "-t", "100",
           "-timeout", "30", "-ssl", "-a"]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    # subjack outputs clean text: [Not Vulnerable] domain.com
    results = []
    for line in read_lines(output_file):
        line = strip_ansi(line).strip()
        if not line or line.startswith("-"):
            continue
        results.append(line)

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

    return _parse_subzy_output(output_file, stdout)


def run_nuclei_takeover(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei with takeover templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        logger.tool_not_found("nuclei")
        return []

    logger.info("Running nuclei takeover templates...")
    cmd = [tool, "-l", input_file, "-t", "http/takeovers/", "-o", output_file, "-silent"]
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

    sj_results = run_subjack(subdomains_file, sj_file, logger)
    sz_results = run_subzy(subdomains_file, sz_file, logger)
    nt_results = run_nuclei_takeover(subdomains_file, nt_file, logger)

    # Merge and deduplicate by subdomain
    vulnerable = {}
    not_vulnerable = set()

    for line in sj_results + sz_results:
        if "VULNERABLE" in line and "NOT VULNERABLE" not in line:
            # Extract subdomain and engine
            match = re.search(r"-\s+(\S+)\s+\[\s*(.+?)\s*\]", line)
            if match:
                sub, engine = match.group(1), match.group(2)
                vulnerable[sub] = engine
        elif "NOT VULNERABLE" in line or "Not Vulnerable" in line:
            match = re.search(r"-\s+(\S+)", line)
            if match:
                not_vulnerable.add(match.group(1))

    # Nuclei results
    for line in nt_results:
        line = strip_ansi(line).strip()
        if line:
            # nuclei output format varies, just include as-is
            vulnerable[f"nuclei: {line}"] = "nuclei"

    # Remove from not_vulnerable if also in vulnerable
    not_vulnerable -= set(vulnerable.keys())

    # Build clean output
    final = []
    if vulnerable:
        final.append("=== VULNERABLE ===")
        for sub in sorted(vulnerable.keys()):
            final.append(f"  {sub}  [ {vulnerable[sub]} ]")

    if not_vulnerable:
        final.append("")
        final.append("=== NOT VULNERABLE ===")
        for sub in sorted(not_vulnerable):
            final.append(f"  {sub}")

    takeover_file = os.path.join(scan_dir, "takeover_results.txt")
    write_lines(takeover_file, final)

    vuln_count = len(vulnerable)
    logger.found_count("VULNERABLE takeovers", vuln_count)
    logger.found_count("not vulnerable", len(not_vulnerable))
    logger.phase_end(12, "Subdomain Takeover", vuln_count)
    return takeover_file
