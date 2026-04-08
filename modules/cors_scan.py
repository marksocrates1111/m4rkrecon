"""
Phase 15: CORS Misconfiguration Scanning
Tools: Corsy (primary), CORScanner (fallback)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def run_corsy(input_file: str, output_file: str, logger) -> list[str]:
    """Run Corsy CORS misconfiguration scanner."""
    tool = TOOLS["corsy"]
    if not tool_exists(tool):
        logger.tool_not_found("corsy")
        return []

    logger.info("Running Corsy CORS scanner...")
    cmd = [
        "python3", tool,
        "-i", input_file,
        "-o", output_file,
        "-t", str(min(THREADS, 20)),
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    results = read_lines(output_file)
    logger.found_count("CORS misconfigurations", len(results))
    return results


def run_cors_check_builtin(urls_file: str, output_file: str, logger) -> list[str]:
    """Built-in CORS check when external tools aren't available."""
    import requests
    logger.info("Running built-in CORS checker...")

    urls = read_lines(urls_file)[:50]  # Limit
    findings = []

    for url in urls:
        try:
            # Test with arbitrary origin
            headers = {"Origin": "https://evil.com"}
            resp = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "https://evil.com":
                finding = f"[CRITICAL] {url} - Reflects arbitrary origin"
                if acac.lower() == "true":
                    finding += " + credentials allowed"
                findings.append(finding)
                logger.success(finding)
            elif acao == "*":
                finding = f"[MEDIUM] {url} - Wildcard ACAO (*)"
                findings.append(finding)
            elif acao == "null":
                finding = f"[HIGH] {url} - Null origin allowed"
                findings.append(finding)

        except Exception:
            continue

    write_lines(output_file, findings)
    return findings


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 15: CORS Misconfiguration Scan."""
    logger.phase_start(15, "CORS Misconfiguration Scan", "Corsy / built-in")

    urls_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(urls_file):
        logger.warning("No live URLs - skipping CORS scan")
        logger.phase_end(15, "CORS Scan", 0)
        return ""

    cors_file = os.path.join(scan_dir, "cors_results.txt")

    # Try Corsy first, fall back to built-in
    if tool_exists(TOOLS.get("corsy", "")):
        run_corsy(urls_file, cors_file, logger)
    else:
        run_cors_check_builtin(urls_file, cors_file, logger)

    results = read_lines(cors_file)
    logger.phase_end(15, "CORS Scan", len(results))
    return cors_file
