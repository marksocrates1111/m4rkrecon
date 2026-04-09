"""
Phase 10: Parameter Discovery
Tools: arjun, paramspider, + extract from crawled URLs
"""

import os
from urllib.parse import urlparse, parse_qs
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def extract_params_from_urls(urls_file: str, output_file: str, logger) -> list[str]:
    """Extract URLs that already contain parameters from crawled URLs.
    This is the most important source - gau/waybackurls/katana find thousands
    of parameterized URLs that should be tested for XSS/SQLi/SSRF."""
    urls = read_lines(urls_file)
    parameterized = []
    seen_patterns = set()

    for url in urls:
        if "=" not in url:
            continue
        try:
            parsed = urlparse(url)
            if not parsed.hostname or not parsed.query:
                continue
            # Skip static files
            path_lower = parsed.path.lower()
            if path_lower.endswith((".css", ".js", ".png", ".jpg", ".jpeg",
                                    ".gif", ".svg", ".ico", ".woff", ".woff2",
                                    ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
                                    ".zip", ".map")):
                continue
            # Deduplicate by base+param_names (avoid testing same endpoint with different values)
            params = sorted(parse_qs(parsed.query).keys())
            pattern = f"{parsed.scheme}://{parsed.hostname}{parsed.path}?{'&'.join(params)}"
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                parameterized.append(url)
        except Exception:
            continue

    write_lines(output_file, parameterized)
    logger.found_count("parameterized URLs from crawl", len(parameterized))
    return parameterized


def run_arjun(target_url: str, output_file: str, logger) -> list[str]:
    """Run arjun for hidden parameter discovery on a single URL."""
    tool = TOOLS["arjun"]
    if not tool_exists(tool):
        return []

    cmd = [
        tool,
        "-u", target_url,
        "-oT", output_file,
        "-t", str(min(THREADS, 15)),
        "--stable",
        "--timeout", "10",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=120)
    return read_lines(output_file)


def run_paramspider(domain: str, output_dir: str, logger) -> list[str]:
    """Run paramspider for parameter mining from web archives."""
    tool = TOOLS["paramspider"]
    if not tool_exists(tool):
        logger.tool_not_found("paramspider")
        return []

    logger.info("Running paramspider...")
    cmd = [tool, "-d", domain, "--output", output_dir, "--level", "high"]
    rc, stdout, stderr = run_command(cmd, timeout=180)

    result_file = os.path.join(output_dir, f"{domain}.txt")
    if os.path.isfile(result_file):
        results = read_lines(result_file)
        logger.found_count("parameterized URLs (paramspider)", len(results))
        return results

    return []


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 10: Parameter Discovery."""
    logger.phase_start(10, "Parameter Discovery", "URL extraction + arjun + paramspider")

    phase_dir = os.path.join(scan_dir, "phase10_params")
    os.makedirs(phase_dir, exist_ok=True)

    all_params = []

    # Step 1: Extract parameterized URLs from already-crawled URLs (MOST IMPORTANT)
    all_urls_file = os.path.join(scan_dir, "all_urls.txt")
    if os.path.isfile(all_urls_file):
        extracted_file = os.path.join(phase_dir, "extracted_params.txt")
        extracted = extract_params_from_urls(all_urls_file, extracted_file, logger)
        all_params.extend(extracted)

    # Step 2: Run paramspider for archive mining
    ps_dir = os.path.join(phase_dir, "paramspider")
    os.makedirs(ps_dir, exist_ok=True)
    ps_results = run_paramspider(domain, ps_dir, logger)
    all_params.extend(ps_results)

    # Step 3: Run arjun on key live URLs for hidden param discovery
    urls_file = os.path.join(scan_dir, "live_urls.txt")
    if os.path.isfile(urls_file):
        live_urls = read_lines(urls_file)
        targets = live_urls[:10]

        has_arjun = tool_exists(TOOLS["arjun"])
        if has_arjun:
            logger.info(f"Running arjun on {len(targets)} targets...")
            for i, url in enumerate(targets):
                out_file = os.path.join(phase_dir, f"arjun_{i}.txt")
                results = run_arjun(url, out_file, logger)
                all_params.extend(results)
        else:
            logger.tool_not_found("arjun")

    # Deduplicate and write
    unique_params = sorted(set(all_params))
    params_file = os.path.join(scan_dir, "parameters.txt")
    write_lines(params_file, unique_params)

    logger.phase_end(10, "Parameter Discovery", len(unique_params))
    return params_file
