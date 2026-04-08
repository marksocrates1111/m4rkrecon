"""
Phase 9: Directory & File Bruteforce
Tools: ffuf (primary), dirsearch (fallback)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS, WORDLISTS


def run_ffuf(target_url: str, output_file: str, logger) -> list[str]:
    """Run ffuf for directory bruteforce on a single target."""
    tool = TOOLS["ffuf"]
    if not tool_exists(tool):
        return []

    wordlist = WORDLISTS.get("directories", "")
    if not os.path.isfile(wordlist):
        logger.warning("Directory wordlist not found")
        return []

    cmd = [
        tool,
        "-u", f"{target_url}/FUZZ",
        "-w", wordlist,
        "-o", output_file,
        "-of", "csv",
        "-t", str(min(THREADS, 40)),
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-ac",             # auto-calibrate filtering
        "-s",              # silent
        "-timeout", "10",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)
    return read_lines(output_file)


def run_dirsearch(target_url: str, output_file: str, logger) -> list[str]:
    """Run dirsearch as fallback."""
    tool = TOOLS["dirsearch"]
    if not tool_exists(tool):
        return []

    cmd = [
        tool,
        "-u", target_url,
        "-o", output_file,
        "--format", "plain",
        "-t", str(min(THREADS, 30)),
        "-q",              # quiet
        "--timeout", "10",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)
    return read_lines(output_file)


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 9: Directory Bruteforce."""
    logger.phase_start(9, "Directory & File Bruteforce", "ffuf / dirsearch")

    urls_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(urls_file):
        logger.warning("No live URLs - skipping directory bruteforce")
        logger.phase_end(9, "Dir Bruteforce", 0)
        return ""

    phase_dir = os.path.join(scan_dir, "phase9_dirs")
    os.makedirs(phase_dir, exist_ok=True)

    live_urls = read_lines(urls_file)
    # Limit to top 10 targets to avoid excessive scanning
    targets = live_urls[:10]
    logger.info(f"Bruteforcing directories on {len(targets)} targets...")

    all_results = []
    has_ffuf = tool_exists(TOOLS["ffuf"])
    has_dirsearch = tool_exists(TOOLS["dirsearch"])

    if not has_ffuf and not has_dirsearch:
        logger.tool_not_found("ffuf/dirsearch")
        logger.phase_end(9, "Dir Bruteforce", 0)
        return ""

    for i, url in enumerate(targets):
        sanitized = url.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
        out_file = os.path.join(phase_dir, f"{sanitized}.txt")

        if has_ffuf:
            results = run_ffuf(url, out_file, logger)
        else:
            results = run_dirsearch(url, out_file, logger)

        all_results.extend(results)
        if (i + 1) % 5 == 0:
            logger.info(f"  Completed {i + 1}/{len(targets)} targets")

    # Write merged results
    dirs_file = os.path.join(scan_dir, "directories.txt")
    write_lines(dirs_file, sorted(set(all_results)))

    logger.phase_end(9, "Dir Bruteforce", len(all_results))
    return dirs_file
