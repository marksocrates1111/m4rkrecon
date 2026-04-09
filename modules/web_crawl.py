"""
Phase 7: Web Crawling & URL Discovery
Tools: katana, waybackurls, gau, Wayback CDX API
"""

import os
import requests
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS


def run_wayback_cdx(domain: str, output_file: str, logger) -> list[str]:
    """Query Wayback Machine CDX API directly for archived URLs.
    This is the GOLD MINE - returns thousands of historical URLs with parameters."""
    logger.info("Querying Wayback CDX API...")
    try:
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*"
            f"&fl=original"
            f"&collapse=urlkey"
            f"&output=text"
        )
        resp = requests.get(url, timeout=60)
        if resp.status_code != 200:
            logger.warning(f"CDX API returned {resp.status_code}")
            return []

        urls = [line.strip() for line in resp.text.split("\n") if line.strip()]
        # Filter out static files
        filtered = []
        skip_ext = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
            ".zip", ".gz", ".tar", ".map", ".webp", ".avif",
        )
        for u in urls:
            if not any(u.lower().endswith(ext) for ext in skip_ext):
                filtered.append(u)

        write_lines(output_file, filtered)
        logger.found_count("URLs (Wayback CDX)", len(filtered))
        return filtered

    except Exception as e:
        logger.warning(f"CDX API error: {e}")
        return []


def run_katana(input_file: str, output_file: str, logger) -> list[str]:
    """Run katana for active web crawling."""
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
        "-d", "3",
        "-c", str(THREADS),
        "-jc",
        "-kf", "all",
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


def run_uro_dedup(input_file: str, output_file: str, logger) -> list[str]:
    """Run uro to intelligently deduplicate URLs.
    uro removes similar URLs keeping only unique parameter patterns."""
    uro_path = TOOLS.get("uro", "uro")
    if not tool_exists(uro_path):
        # Fallback: basic dedup
        logger.info("uro not found, using basic dedup...")
        urls = read_lines(input_file)
        unique = sorted(set(urls))
        write_lines(output_file, unique)
        return unique

    logger.info("Running uro for smart URL deduplication...")
    urls = read_lines(input_file)
    stdin_data = "\n".join(urls)
    cmd = [uro_path]
    rc, stdout, stderr = run_command(cmd, output_file=output_file, timeout=120, stdin_data=stdin_data)

    results = read_lines(output_file)
    logger.found_count("URLs after uro dedup", len(results))
    return results


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 7: Web Crawling & URL Discovery."""
    logger.phase_start(7, "Web Crawling & URL Discovery", "CDX API + katana + gau + waybackurls + uro")

    phase_dir = os.path.join(scan_dir, "phase7_crawl")
    os.makedirs(phase_dir, exist_ok=True)

    urls_file = os.path.join(scan_dir, "live_urls.txt")

    cdx_file = os.path.join(phase_dir, "wayback_cdx.txt")
    katana_file = os.path.join(phase_dir, "katana.txt")
    wb_file = os.path.join(phase_dir, "waybackurls.txt")
    gau_file = os.path.join(phase_dir, "gau.txt")

    # 1. Wayback CDX API (direct, most comprehensive)
    run_wayback_cdx(domain, cdx_file, logger)

    # 2. Katana active crawl (needs live URLs)
    if os.path.isfile(urls_file):
        run_katana(urls_file, katana_file, logger)

    # 3. waybackurls + gau
    run_waybackurls(domain, wb_file, logger)
    run_gau(domain, gau_file, logger)

    # 4. Merge all URLs
    raw_merged = os.path.join(phase_dir, "raw_merged.txt")
    all_lines = set()
    for f in [cdx_file, katana_file, wb_file, gau_file]:
        all_lines.update(read_lines(f))
    write_lines(raw_merged, sorted(all_lines))
    logger.info(f"Total raw URLs before dedup: {len(all_lines)}")

    # 5. Smart dedup with uro
    all_urls_file = os.path.join(scan_dir, "all_urls.txt")
    run_uro_dedup(raw_merged, all_urls_file, logger)

    final_count = len(read_lines(all_urls_file))
    logger.phase_end(7, "URL Discovery", final_count)
    return all_urls_file
