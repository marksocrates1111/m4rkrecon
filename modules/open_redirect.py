"""
Phase 16: Open Redirect Detection
Techniques from KingOfBugBountyTips + 0xPugal one-liners.
Pipeline: gf redirect → qsreplace payload → curl Location check
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "////evil.com",
    "https://evil.com/%2f..",
    "///evil.com@evil.com",
    "/%09/evil.com",
    "//%0Devil.com",
]


def run_redirect_qsreplace(input_file: str, output_file: str, logger) -> list[str]:
    """Open redirect check via qsreplace + curl Location header.
    One-liner: gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % sh -c
    'curl -Is "%" | grep -q "Location: $LHOST" && echo "VULN! %"'"""
    qsreplace = TOOLS.get("qsreplace", "qsreplace")
    httpx = TOOLS["httpx"]

    if not tool_exists(qsreplace) or not tool_exists(httpx):
        return []

    urls = read_lines(input_file)
    if not urls:
        return []

    logger.info(f"Testing {len(urls)} URLs for open redirects...")
    findings = []

    for payload in REDIRECT_PAYLOADS[:3]:  # Top 3 payloads
        stdin_data = "\n".join(urls)
        cmd_qs = [qsreplace, payload]
        rc, replaced, _ = run_command(cmd_qs, timeout=30, stdin_data=stdin_data)
        if not replaced:
            continue

        # Check for redirect to evil.com in Location header
        cmd_httpx = [
            httpx, "-silent", "-nc",
            "-mc", "301,302,303,307,308",
            "-mr", "evil.com",
            "-t", str(min(THREADS, 20)),
            "-location",
        ]
        rc, stdout, _ = run_command(cmd_httpx, timeout=60, stdin_data=replaced)
        if stdout:
            for line in stdout.strip().split("\n"):
                if line.strip() and "evil.com" in line:
                    findings.append(f"[REDIRECT] {line.strip()}")

    unique = sorted(set(findings))
    write_lines(output_file, unique)
    logger.found_count("open redirects (qsreplace)", len(unique))
    return unique


def run_nuclei_redirect(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei open redirect templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei open redirect templates...")
    cmd = [
        tool, "-l", input_file,
        "-tags", "redirect",
        "-o", output_file, "-silent", "-rl", "30",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("open redirects (nuclei)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 16: Open Redirect Detection - multi-technique."""
    logger.phase_start(16, "Open Redirect Detection", "qsreplace + nuclei")

    redir_file = os.path.join(scan_dir, "urls_redirect.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(redir_file) and read_lines(redir_file):
        source = redir_file
        logger.info(f"Using {len(read_lines(source))} redirect-categorized URLs")
    elif os.path.isfile(params_file) and read_lines(params_file):
        source = params_file
    else:
        logger.warning("No parameterized URLs - skipping redirect detection")
        logger.phase_end(16, "Open Redirect", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase16_redirect")
    os.makedirs(phase_dir, exist_ok=True)

    all_results = []

    # Technique 1: qsreplace + httpx redirect check
    qs_file = os.path.join(phase_dir, "qsreplace_redirect.txt")
    qs_results = run_redirect_qsreplace(source, qs_file, logger)
    all_results.extend(qs_results)

    # Technique 2: nuclei redirect templates
    nuclei_file = os.path.join(phase_dir, "nuclei_redirect.txt")
    nuclei_results = run_nuclei_redirect(source, nuclei_file, logger)
    all_results.extend(nuclei_results)

    redirect_results = os.path.join(scan_dir, "redirect_results.txt")
    write_lines(redirect_results, sorted(set(all_results)))

    logger.phase_end(16, "Open Redirect", len(set(all_results)))
    return redirect_results
