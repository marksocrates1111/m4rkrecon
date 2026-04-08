"""
Phase 16: Open Redirect Detection
Tools: OpenRedireX (primary), built-in checker (fallback)
"""

import os
import requests
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS


REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "rurl", "next", "next_url", "target", "dest", "destination",
    "redir", "redirect_to", "out", "view", "login", "logout", "goto", "link",
    "forward", "continue", "ReturnUrl", "callback", "path", "data", "reference",
    "site", "html", "backurl", "fromurl", "ref",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2f..",
]


def run_openredirex(input_file: str, output_file: str, logger) -> list[str]:
    """Run OpenRedireX for open redirect detection."""
    tool = TOOLS["openredirex"]
    if not tool_exists(tool):
        logger.tool_not_found("openredirex")
        return []

    logger.info("Running OpenRedireX...")
    cmd = [
        "python3", tool,
        "-l", input_file,
        "-p", "https://evil.com",
        "--keyword", "FUZZ",
    ]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=300)

    results = read_lines(output_file)
    logger.found_count("open redirects", len(results))
    return results


def check_redirect_builtin(urls_file: str, output_file: str, logger) -> list[str]:
    """Built-in open redirect checker."""
    logger.info("Running built-in redirect checker...")
    urls = read_lines(urls_file)
    findings = []

    # Filter URLs with redirect-like parameters
    candidate_urls = []
    for url in urls:
        for param in REDIRECT_PARAMS:
            if param in url.lower():
                candidate_urls.append(url)
                break

    candidate_urls = candidate_urls[:30]  # Limit
    logger.info(f"Testing {len(candidate_urls)} URLs with redirect parameters...")

    for url in candidate_urls:
        for payload in REDIRECT_PAYLOADS:
            try:
                # Replace parameter values with payload
                test_url = url
                for param in REDIRECT_PARAMS:
                    if f"{param}=" in test_url.lower():
                        parts = test_url.split("?", 1)
                        if len(parts) == 2:
                            base, qs = parts
                            # Simple replacement
                            import re
                            qs = re.sub(
                                f"({param})=[^&]*",
                                f"\\1={payload}",
                                qs,
                                flags=re.IGNORECASE,
                            )
                            test_url = f"{base}?{qs}"

                resp = requests.get(
                    test_url,
                    allow_redirects=False,
                    timeout=5,
                    verify=False,
                )
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    finding = f"[REDIRECT] {test_url} -> {location}"
                    findings.append(finding)
                    logger.success(finding)
                    break  # One payload enough per URL

            except Exception:
                continue

    write_lines(output_file, findings)
    return findings


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 16: Open Redirect Detection."""
    logger.phase_start(16, "Open Redirect Detection", "OpenRedireX / built-in")

    urls_file = os.path.join(scan_dir, "all_urls.txt")
    if not os.path.isfile(urls_file):
        urls_file = os.path.join(scan_dir, "live_urls.txt")
    if not os.path.isfile(urls_file):
        logger.warning("No URLs - skipping redirect detection")
        logger.phase_end(16, "Open Redirect", 0)
        return ""

    redirect_file = os.path.join(scan_dir, "redirect_results.txt")

    if tool_exists(TOOLS.get("openredirex", "")):
        run_openredirex(urls_file, redirect_file, logger)
    else:
        check_redirect_builtin(urls_file, redirect_file, logger)

    logger.phase_end(16, "Open Redirect", len(read_lines(redirect_file)))
    return redirect_file
