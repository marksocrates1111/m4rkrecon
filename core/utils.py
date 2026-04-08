"""M4rkRecon - Utility functions for file I/O, dedup, domain validation."""

import os
import re
import json
from datetime import datetime
from urllib.parse import urlparse


def validate_domain(domain: str) -> bool:
    """Validate domain format."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain.strip()))


def create_scan_dir(base_output_dir: str, domain: str) -> str:
    """Create a timestamped output directory for this scan."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized = domain.replace(".", "_")
    scan_dir = os.path.join(base_output_dir, f"{sanitized}_{timestamp}")
    os.makedirs(scan_dir, exist_ok=True)
    return scan_dir


def read_lines(filepath: str) -> list[str]:
    """Read non-empty lines from a file."""
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def write_lines(filepath: str, lines: list[str]):
    """Write lines to a file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def append_lines(filepath: str, lines: list[str]):
    """Append lines to a file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def dedup_lines(filepath: str) -> list[str]:
    """Read, deduplicate, sort, and rewrite a file. Returns unique lines."""
    lines = read_lines(filepath)
    unique = sorted(set(lines))
    write_lines(filepath, unique)
    return unique


def merge_files(input_files: list[str], output_file: str) -> list[str]:
    """Merge multiple files into one, deduplicated."""
    all_lines = set()
    for f in input_files:
        all_lines.update(read_lines(f))
    unique = sorted(all_lines)
    write_lines(output_file, unique)
    return unique


def write_json(filepath: str, data):
    """Write data as JSON."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def read_json(filepath: str):
    """Read JSON file."""
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_jsonl(filepath: str) -> list[dict]:
    """Parse a JSONL (JSON Lines) file."""
    results = []
    if not os.path.isfile(filepath):
        return results
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return results


def extract_domains_from_urls(urls: list[str]) -> list[str]:
    """Extract unique domains from a list of URLs."""
    domains = set()
    for url in urls:
        try:
            parsed = urlparse(url if "://" in url else f"https://{url}")
            if parsed.hostname:
                domains.add(parsed.hostname)
        except Exception:
            continue
    return sorted(domains)


def count_results(filepath: str) -> int:
    """Count non-empty lines in a file."""
    return len(read_lines(filepath))


def file_size_readable(filepath: str) -> str:
    """Get human-readable file size."""
    if not os.path.isfile(filepath):
        return "0 B"
    size = os.path.getsize(filepath)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
