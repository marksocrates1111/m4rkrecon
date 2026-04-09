"""
Phase 10: Parameter Discovery
Extract parameterized URLs from crawled data + categorize by vuln type.
Tools: URL extraction, paramspider, arjun, gf-patterns
"""

import os
from urllib.parse import urlparse, parse_qs
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS, THREADS

# GF-style patterns: map URL parameter names to likely vulnerability types
VULN_PARAM_PATTERNS = {
    "xss": [
        "q", "s", "search", "query", "keyword", "term", "text", "name",
        "message", "comment", "body", "title", "desc", "description",
        "content", "value", "input", "data", "html", "err", "error",
        "msg", "feedback", "review",
    ],
    "sqli": [
        "id", "page", "report", "dir", "search", "category", "file",
        "class", "url", "news", "item", "menu", "lang", "name", "ref",
        "title", "view", "topic", "thread", "type", "date", "cat",
        "sort", "order", "process", "row", "tab", "group", "column",
        "field", "result", "role", "update", "query", "user", "select",
        "from", "table", "where", "join",
    ],
    "ssrf": [
        "url", "uri", "path", "dest", "redirect", "file", "page", "feed",
        "host", "site", "html", "data", "reference", "ref", "img", "src",
        "load", "target", "proxy", "port", "to", "out", "view", "domain",
        "callback", "return", "fetch", "next", "content", "document",
    ],
    "redirect": [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnTo", "rurl", "next", "next_url", "target",
        "dest", "destination", "redir", "redirect_to", "out", "view",
        "login", "logout", "goto", "link", "forward", "continue",
        "ReturnUrl", "callback", "path", "data", "reference", "site",
        "backurl", "fromurl", "ref",
    ],
    "lfi": [
        "file", "document", "folder", "root", "path", "pg", "style",
        "pdf", "template", "php_path", "doc", "page", "name", "cat",
        "dir", "action", "board", "date", "detail", "download", "prefix",
        "include", "inc", "locate", "show", "site", "type", "view",
        "content", "layout", "mod", "conf", "lang",
    ],
}


def extract_parameterized_urls(urls_file: str, output_file: str, logger) -> list[str]:
    """Extract URLs containing query parameters from crawled URLs.
    Deduplicates by endpoint + parameter name pattern."""
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
            # Skip junk
            path_lower = parsed.path.lower()
            if path_lower.endswith((".css", ".js", ".png", ".jpg", ".jpeg",
                                    ".gif", ".svg", ".ico", ".woff", ".woff2",
                                    ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
                                    ".zip", ".map", ".webp")):
                continue
            # Dedup by base + param names
            params = sorted(parse_qs(parsed.query).keys())
            pattern = f"{parsed.hostname}{parsed.path}?{'&'.join(params)}"
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                parameterized.append(url)
        except Exception:
            continue

    write_lines(output_file, parameterized)
    logger.found_count("parameterized URLs extracted", len(parameterized))
    return parameterized


def categorize_urls_by_vuln(params_file: str, output_dir: str, logger) -> dict:
    """Categorize parameterized URLs by likely vulnerability type
    based on parameter names (like gf patterns)."""
    urls = read_lines(params_file)
    categories = {vtype: [] for vtype in VULN_PARAM_PATTERNS}

    for url in urls:
        try:
            parsed = urlparse(url)
            param_names = [k.lower() for k in parse_qs(parsed.query).keys()]

            for vtype, patterns in VULN_PARAM_PATTERNS.items():
                if any(p in param_names for p in patterns):
                    categories[vtype].append(url)
        except Exception:
            continue

    # Write each category to its own file
    for vtype, vurls in categories.items():
        unique = sorted(set(vurls))
        if unique:
            cat_file = os.path.join(output_dir, f"urls_{vtype}.txt")
            write_lines(cat_file, unique)
            logger.found_count(f"URLs with {vtype}-like params", len(unique))

    return categories


def run_paramspider(domain: str, output_dir: str, logger) -> list[str]:
    """Run paramspider for archive-based parameter mining."""
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
        logger.found_count("URLs (paramspider)", len(results))
        return results
    return []


def run_arjun(target_url: str, output_file: str, logger) -> list[str]:
    """Run arjun for hidden parameter discovery."""
    tool = TOOLS["arjun"]
    if not tool_exists(tool):
        return []
    cmd = [tool, "-u", target_url, "-oT", output_file,
           "-t", str(min(THREADS, 15)), "--stable", "--timeout", "10"]
    rc, stdout, stderr = run_command(cmd, timeout=120)
    return read_lines(output_file)


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 10: Parameter Discovery & Categorization."""
    logger.phase_start(10, "Parameter Discovery & Categorization",
                       "URL extraction + paramspider + arjun + gf-patterns")

    phase_dir = os.path.join(scan_dir, "phase10_params")
    os.makedirs(phase_dir, exist_ok=True)

    all_params = []

    # Step 1: Extract parameterized URLs from crawled URLs (MOST IMPORTANT)
    all_urls_file = os.path.join(scan_dir, "all_urls.txt")
    if os.path.isfile(all_urls_file):
        extracted_file = os.path.join(phase_dir, "extracted_params.txt")
        extracted = extract_parameterized_urls(all_urls_file, extracted_file, logger)
        all_params.extend(extracted)

    # Step 2: ParamSpider for additional archive mining
    ps_dir = os.path.join(phase_dir, "paramspider")
    os.makedirs(ps_dir, exist_ok=True)
    ps_results = run_paramspider(domain, ps_dir, logger)
    all_params.extend(ps_results)

    # Step 3: Arjun on key endpoints for hidden params
    urls_file = os.path.join(scan_dir, "live_urls.txt")
    if os.path.isfile(urls_file):
        live_urls = read_lines(urls_file)
        has_arjun = tool_exists(TOOLS["arjun"])
        if has_arjun:
            targets = live_urls[:10]
            logger.info(f"Running arjun on {len(targets)} targets...")
            for i, url in enumerate(targets):
                out_file = os.path.join(phase_dir, f"arjun_{i}.txt")
                results = run_arjun(url, out_file, logger)
                all_params.extend(results)

    # Deduplicate all params
    unique_params = sorted(set(all_params))
    params_file = os.path.join(scan_dir, "parameters.txt")
    write_lines(params_file, unique_params)

    # Step 4: Categorize by vulnerability type (gf-pattern style)
    logger.info("Categorizing URLs by vulnerability type...")
    categorize_urls_by_vuln(params_file, phase_dir, logger)

    # Also write categorized files to scan_dir for easy access by other phases
    for vtype in ["xss", "sqli", "ssrf", "redirect", "lfi"]:
        src = os.path.join(phase_dir, f"urls_{vtype}.txt")
        dst = os.path.join(scan_dir, f"urls_{vtype}.txt")
        if os.path.isfile(src):
            urls = read_lines(src)
            write_lines(dst, urls)

    logger.phase_end(10, "Parameter Discovery", len(unique_params))
    return params_file
