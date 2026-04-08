"""
Phase 10: Parameter Discovery
Tools: arjun (primary), paramspider (fallback)
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, merge_files
from config import TOOLS, THREADS


def run_arjun(target_url: str, output_file: str, logger) -> list[str]:
    """Run arjun for parameter discovery on a single URL."""
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

    # ParamSpider outputs to a file named after the domain
    result_file = os.path.join(output_dir, f"{domain}.txt")
    if os.path.isfile(result_file):
        results = read_lines(result_file)
        logger.found_count("parameterized URLs (paramspider)", len(results))
        return results

    return []


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 10: Parameter Discovery."""
    logger.phase_start(10, "Parameter Discovery", "arjun + paramspider")

    phase_dir = os.path.join(scan_dir, "phase10_params")
    os.makedirs(phase_dir, exist_ok=True)

    urls_file = os.path.join(scan_dir, "live_urls.txt")
    all_params = []

    # Run arjun on top live URLs
    if os.path.isfile(urls_file):
        live_urls = read_lines(urls_file)
        targets = live_urls[:5]  # Limit for speed

        has_arjun = tool_exists(TOOLS["arjun"])
        if has_arjun:
            logger.info(f"Running arjun on {len(targets)} targets...")
            for i, url in enumerate(targets):
                out_file = os.path.join(phase_dir, f"arjun_{i}.txt")
                results = run_arjun(url, out_file, logger)
                all_params.extend(results)
        else:
            logger.tool_not_found("arjun")

    # Run paramspider for archive mining
    ps_dir = os.path.join(phase_dir, "paramspider")
    os.makedirs(ps_dir, exist_ok=True)
    ps_results = run_paramspider(domain, ps_dir, logger)
    all_params.extend(ps_results)

    # Write results
    params_file = os.path.join(scan_dir, "parameters.txt")
    write_lines(params_file, sorted(set(all_params)))

    logger.phase_end(10, "Parameter Discovery", len(set(all_params)))
    return params_file
