"""
Phase 7: Web Crawling & URL Discovery
Tools: katana, waybackurls, gau
"""

import os
from core.runner import run_command, tool_exists
from core.utils import read_lines, merge_files
from config import TOOLS, THREADS


def run_katana(input_file: str, output_file: str, logger) -> list[str]:
    """Run katana for web crawling."""
    tool = TOOLS["katana"]
    if not tool_exists(tool):
        logger.tool_not_found("katana")
        return []

    logger.info("Running katana web crawler...")
    cmd = [
        tool,
        "-list", input_file,
        "-o", output_file,
        "-silent",
        "-d", "3",             # crawl depth
        "-c", str(THREADS),
        "-jc",                  # crawl JS files
        "-kf", "all",          # known file types
        "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
    ]
    rc, stdout, stderr = run_command(cmd, timeout=600)

    results = read_lines(output_file)
    logger.found_count("URLs (katana)", len(results))
    return results


def run_waybackurls(domain: str, output_file: str, logger) -> list[str]:
    """Run waybackurls for historical URL discovery."""
    tool = TOOLS["waybackurls"]
    if not tool_exists(tool):
        logger.tool_not_found("waybackurls")
        return []

    logger.info("Running waybackurls...")
    cmd = [tool, domain]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=120)

    results = read_lines(output_file)
    logger.found_count("URLs (waybackurls)", len(results))
    return results


def run_gau(domain: str, output_file: str, logger) -> list[str]:
    """Run gau (GetAllUrls) for URL discovery from multiple sources."""
    tool = TOOLS["gau"]
    if not tool_exists(tool):
        logger.tool_not_found("gau")
        return []

    logger.info("Running gau...")
    cmd = [tool, domain, "--o", output_file, "--threads", str(THREADS)]
    rc, stdout, stderr = run_command(cmd, timeout=180)

    results = read_lines(output_file)
    logger.found_count("URLs (gau)", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 7: Web Crawling & URL Discovery."""
    logger.phase_start(7, "Web Crawling & URL Discovery", "katana + waybackurls + gau")

    phase_dir = os.path.join(scan_dir, "phase7_crawl")
    os.makedirs(phase_dir, exist_ok=True)

    urls_file = os.path.join(scan_dir, "live_urls.txt")

    katana_file = os.path.join(phase_dir, "katana.txt")
    wb_file = os.path.join(phase_dir, "waybackurls.txt")
    gau_file = os.path.join(phase_dir, "gau.txt")

    # Katana needs live URLs, others just need domain
    if os.path.isfile(urls_file):
        run_katana(urls_file, katana_file, logger)

    run_waybackurls(domain, wb_file, logger)
    run_gau(domain, gau_file, logger)

    # Merge all URLs
    all_urls_file = os.path.join(scan_dir, "all_urls.txt")
    merged = merge_files([katana_file, wb_file, gau_file], all_urls_file)

    logger.phase_end(7, "URL Discovery", len(merged))
    return all_urls_file
