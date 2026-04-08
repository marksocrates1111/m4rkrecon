"""
Phase 4: Live Host Detection + Technology Fingerprinting
Tools: httpx
"""

import os
import json
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, parse_jsonl
from config import TOOLS, THREADS, RATE_LIMIT


def run_httpx(input_file: str, output_file: str, json_file: str, logger) -> list[str]:
    """Run httpx to probe live hosts with tech detection."""
    tool = TOOLS["httpx"]
    if not tool_exists(tool):
        logger.tool_not_found("httpx")
        return []

    logger.info("Running httpx (probing live hosts + tech detect)...")
    cmd = [
        tool,
        "-l", input_file,
        "-o", output_file,
        "-silent",
        "-sc",              # status code
        "-title",           # page title
        "-td",              # tech detect
        "-server",          # server header
        "-cl",              # content length
        "-location",        # redirect location
        "-t", str(THREADS),
        "-rl", str(RATE_LIMIT),
        "-timeout", "10",
        "-retries", "2",
        "-follow-redirects",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    # Also run JSON output for structured data
    json_cmd = [
        tool,
        "-l", input_file,
        "-json",
        "-o", json_file,
        "-silent",
        "-sc", "-title", "-td", "-server",
        "-t", str(THREADS),
        "-rl", str(RATE_LIMIT),
        "-timeout", "10",
        "-follow-redirects",
    ]
    run_command(json_cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("live hosts", len(results))
    return results


def extract_live_urls(json_file: str, output_file: str) -> list[str]:
    """Extract just the URLs from httpx JSON output."""
    entries = parse_jsonl(json_file)
    urls = []
    for entry in entries:
        url = entry.get("url", "")
        if url:
            urls.append(url)
    write_lines(output_file, sorted(set(urls)))
    return urls


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 4: Live Host Detection."""
    logger.phase_start(4, "Live Host Detection + Tech Fingerprinting", "httpx")

    subdomains_file = os.path.join(scan_dir, "subdomains.txt")
    if not os.path.isfile(subdomains_file):
        logger.warning("No subdomains file found - skipping")
        logger.phase_end(4, "Live Hosts", 0)
        return ""

    live_file = os.path.join(scan_dir, "live_hosts.txt")
    json_file = os.path.join(scan_dir, "httpx_results.json")
    urls_file = os.path.join(scan_dir, "live_urls.txt")

    run_httpx(subdomains_file, live_file, json_file, logger)
    extract_live_urls(json_file, urls_file)

    # Parse tech info for summary
    entries = parse_jsonl(json_file)
    techs = set()
    for e in entries:
        for t in e.get("tech", []):
            techs.add(t)
    if techs:
        logger.info(f"Technologies detected: {', '.join(sorted(techs)[:20])}")

    logger.phase_end(4, "Live Hosts", len(read_lines(urls_file)))
    return urls_file
