"""
Phase 14: SQL Injection Testing
Tools: sqlmap (primary), ghauri (fallback)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS


def run_sqlmap(target_url: str, output_dir: str, logger) -> str:
    """Run sqlmap on a single parameterized URL."""
    tool = TOOLS["sqlmap"]
    if not tool_exists(tool):
        return ""

    cmd = [
        tool,
        "-u", target_url,
        "--batch",              # non-interactive
        "--random-agent",
        "--level", "2",
        "--risk", "2",
        "--threads", "5",
        "--timeout", "15",
        "--output-dir", output_dir,
        "--smart",              # only test params that appear injectable
        "--tamper", "between,randomcase",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)
    return stdout


def run_ghauri(target_url: str, output_file: str, logger) -> str:
    """Run ghauri as sqlmap alternative."""
    tool = TOOLS["ghauri"]
    if not tool_exists(tool):
        return ""

    cmd = [
        tool,
        "-u", target_url,
        "--batch",
        "--random-agent",
        "--level", "2",
        "--risk", "2",
        "--threads", "5",
    ]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=300)
    return stdout


def extract_injectable_urls(urls_file: str, limit: int = 20) -> list[str]:
    """Extract URLs with parameters (likely injectable)."""
    urls = read_lines(urls_file)
    injectable = [u for u in urls if "=" in u]
    # Deduplicate by base URL (different param values same endpoint)
    seen_bases = set()
    unique = []
    for url in injectable:
        base = url.split("?")[0]
        if base not in seen_bases:
            seen_bases.add(base)
            unique.append(url)
    return unique[:limit]


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 14: SQL Injection Testing."""
    logger.phase_start(14, "SQL Injection Testing", "sqlmap + ghauri")

    # Priority: categorized sqli URLs > all parameterized URLs
    sqli_urls_file = os.path.join(scan_dir, "urls_sqli.txt")
    params_file = os.path.join(scan_dir, "parameters.txt")

    if os.path.isfile(sqli_urls_file) and read_lines(sqli_urls_file):
        source_file = sqli_urls_file
        logger.info(f"Using {len(read_lines(source_file))} SQLi-categorized URLs")
    elif os.path.isfile(params_file) and read_lines(params_file):
        source_file = params_file
    else:
        logger.warning("No parameterized URLs - skipping SQLi testing")
        logger.phase_end(14, "SQLi Testing", 0)
        return ""

    injectable_urls = extract_injectable_urls(source_file, limit=20)
    if not injectable_urls:
        logger.info("No parameterized URLs found - skipping SQLi testing")
        logger.phase_end(14, "SQLi Testing", 0)
        return ""

    logger.info(f"Testing {len(injectable_urls)} parameterized URLs for SQLi...")

    phase_dir = os.path.join(scan_dir, "phase14_sqli")
    os.makedirs(phase_dir, exist_ok=True)

    has_sqlmap = tool_exists(TOOLS["sqlmap"])
    has_ghauri = tool_exists(TOOLS["ghauri"])

    if not has_sqlmap and not has_ghauri:
        logger.tool_not_found("sqlmap/ghauri")
        logger.phase_end(14, "SQLi Testing", 0)
        return ""

    sqli_findings = []
    for i, url in enumerate(injectable_urls):
        logger.info(f"  Testing [{i+1}/{len(injectable_urls)}]: {url[:80]}...")

        if has_sqlmap:
            out_dir = os.path.join(phase_dir, f"sqlmap_{i}")
            result = run_sqlmap(url, out_dir, logger)
            if result and ("injectable" in result.lower() or "parameter" in result.lower()):
                sqli_findings.append(f"[SQLMAP] {url}")
                logger.success(f"  Potential SQLi found: {url[:80]}")
        elif has_ghauri:
            out_file = os.path.join(phase_dir, f"ghauri_{i}.txt")
            result = run_ghauri(url, out_file, logger)
            if result and "injectable" in result.lower():
                sqli_findings.append(f"[GHAURI] {url}")
                logger.success(f"  Potential SQLi found: {url[:80]}")

    # Write results
    sqli_file = os.path.join(scan_dir, "sqli_results.txt")
    write_lines(sqli_file, sqli_findings)

    logger.phase_end(14, "SQLi Testing", len(sqli_findings))
    return sqli_file
