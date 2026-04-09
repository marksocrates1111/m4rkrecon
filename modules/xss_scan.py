"""
Phase 13: XSS Scanning
Techniques from 0xPugal/One-Liners + KingOfBugBountyTips + dalfox community.
Pipeline: gf xss → qsreplace → reflection check → dalfox deep scan
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def run_reflection_check(input_file: str, output_file: str, logger) -> list[str]:
    """One-liner technique: inject test payload via qsreplace, check reflection with httpx.
    From: cat urls | grep = | qsreplace '<img src=x>' | httpx -mr '<img src=x>'"""
    qsreplace = TOOLS.get("qsreplace", "qsreplace")
    httpx = TOOLS["httpx"]

    if not tool_exists(qsreplace) or not tool_exists(httpx):
        return []

    logger.info("Running reflection check (qsreplace + httpx)...")
    urls = read_lines(input_file)
    payload = "m4rkrec0n1337"
    injected = []
    for url in urls:
        injected.append(url)

    stdin_data = "\n".join(injected)

    # qsreplace replaces all param values with our canary
    cmd_qs = [qsreplace, payload]
    rc, replaced, _ = run_command(cmd_qs, timeout=60, stdin_data=stdin_data)
    if not replaced:
        return []

    # Check which URLs reflect the canary using httpx
    cmd_httpx = [
        httpx, "-silent", "-nc", "-mc", "200",
        "-mr", payload,
        "-t", str(min(THREADS, 30)),
    ]
    rc, stdout, _ = run_command(cmd_httpx, output_file=output_file, timeout=120, stdin_data=replaced)

    results = read_lines(output_file)
    logger.found_count("URLs with reflected params", len(results))
    return results


def run_kxss(input_file: str, output_file: str, logger) -> list[str]:
    """Run kxss to find URLs that reflect special characters."""
    tool = TOOLS["kxss"]
    if not tool_exists(tool):
        return []

    logger.info("Running kxss pre-filter...")
    urls = read_lines(input_file)
    stdin_data = "\n".join(urls)
    cmd = [tool]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=300, stdin_data=stdin_data)

    results = read_lines(output_file)
    logger.found_count("URLs reflecting special chars (kxss)", len(results))
    return results


def run_dalfox(input_file: str, output_file: str, logger, blind_url: str = "") -> list[str]:
    """Run dalfox with deep DOM XSS mining + optional blind XSS callback.
    Techniques from dalfox community one-liners."""
    tool = TOOLS["dalfox"]
    if not tool_exists(tool):
        logger.tool_not_found("dalfox")
        return []

    logger.info("Running dalfox XSS scanner (deep DOM + blind)...")
    cmd = [
        tool,
        "file", input_file,
        "-o", output_file,
        "--silence",
        "--worker", str(min(THREADS, 20)),
        "--timeout", "10",
        "--mining-dom",         # mine DOM XSS sinks
        "--deep-domxss",        # deep DOM XSS analysis
        "--follow-redirects",
    ]
    if blind_url:
        cmd.extend(["-b", blind_url])

    rc, stdout, stderr = run_command(cmd, timeout=900)

    results = read_lines(output_file)
    logger.found_count("XSS vulnerabilities (dalfox)", len(results))
    return results


def run_nuclei_dast_xss(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei DAST XSS templates.
    From: cat urls | nuclei -dast -t dast/vulnerabilities/xss/"""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei DAST XSS templates...")
    cmd = [
        tool,
        "-l", input_file,
        "-t", "dast/vulnerabilities/xss/",
        "-o", output_file,
        "-silent",
        "-rl", "50",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("XSS (nuclei DAST)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 13: XSS Scanning - multi-technique approach."""
    logger.phase_start(13, "XSS Scanning", "reflection check + kxss + dalfox + nuclei DAST")

    # Collect XSS target URLs
    xss_file = os.path.join(scan_dir, "urls_xss.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(xss_file) and read_lines(xss_file):
        source = xss_file
    elif os.path.isfile(params_file) and read_lines(params_file):
        source = params_file
    else:
        logger.warning("No parameterized URLs - skipping XSS scan")
        logger.phase_end(13, "XSS Scan", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase13_xss")
    os.makedirs(phase_dir, exist_ok=True)

    # Cap at 500 URLs
    urls = read_lines(source)[:500]
    scan_file = os.path.join(phase_dir, "xss_targets.txt")
    write_lines(scan_file, urls)
    logger.info(f"Testing {len(urls)} URLs for XSS...")

    all_xss = []

    # Technique 1: Reflection check with qsreplace + httpx
    reflected_file = os.path.join(phase_dir, "reflected.txt")
    reflected = run_reflection_check(scan_file, reflected_file, logger)

    # Technique 2: kxss special char reflection
    kxss_file = os.path.join(phase_dir, "kxss.txt")
    kxss_results = run_kxss(scan_file, kxss_file, logger)

    # Merge reflected URLs for dalfox input
    dalfox_input = os.path.join(phase_dir, "dalfox_input.txt")
    dalfox_targets = set(reflected + kxss_results)
    if not dalfox_targets:
        dalfox_targets = set(urls[:100])  # fallback to raw URLs
    write_lines(dalfox_input, sorted(dalfox_targets))

    # Technique 3: dalfox deep scan with DOM mining
    dalfox_file = os.path.join(phase_dir, "dalfox_results.txt")
    dalfox_results = run_dalfox(dalfox_input, dalfox_file, logger)
    all_xss.extend(dalfox_results)

    # Technique 4: nuclei DAST XSS
    nuclei_xss_file = os.path.join(phase_dir, "nuclei_xss.txt")
    nuclei_results = run_nuclei_dast_xss(scan_file, nuclei_xss_file, logger)
    all_xss.extend(nuclei_results)

    # Write final results
    xss_results_file = os.path.join(scan_dir, "xss_results.txt")
    write_lines(xss_results_file, sorted(set(all_xss)))

    logger.phase_end(13, "XSS Scan", len(set(all_xss)))
    return xss_results_file
