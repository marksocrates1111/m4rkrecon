"""
Phase 8: JavaScript File Analysis & Secret Finding
Tools: SecretFinder, LinkFinder (custom regex fallback)
"""

import os
import re
import requests
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines
from config import TOOLS


# Common secret patterns to search for in JS files
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}\-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    "Heroku API Key": r"(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Stripe API Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,99}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Generic API Key": r"(?i)(?:api[_-]?key|apikey|api_secret|access[_-]?token)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
    "Generic Secret": r"(?i)(?:secret|password|passwd|pwd|token)['\"\s:=]+['\"]?([a-zA-Z0-9_\-]{8,})['\"]?",
    "IP Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "S3 Bucket": r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com",
    "Authorization Header": r"(?i)(?:authorization|bearer)['\"\s:]+['\"]?[a-zA-Z0-9_\-\.=]{20,}['\"]?",
}

# Patterns to extract endpoints from JS files
ENDPOINT_PATTERNS = [
    r'(?:"|\'|\`)(/[a-zA-Z0-9_\-/.]+(?:\?[a-zA-Z0-9_=&]+)?)\1',
    r'(?:href|src|action|url|endpoint|path)\s*[=:]\s*["\']([^"\']+)["\']',
    r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
]


def extract_js_urls(urls_file: str) -> list[str]:
    """Extract JavaScript file URLs from crawled URLs."""
    urls = read_lines(urls_file)
    js_urls = [u for u in urls if re.search(r'\.js(\?|$)', u, re.IGNORECASE)]
    return list(set(js_urls))


def scan_js_content(url: str) -> dict:
    """Download and scan a JS file for secrets and endpoints."""
    findings = {"secrets": [], "endpoints": []}
    try:
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code != 200:
            return findings
        content = resp.text

        # Search for secrets
        for name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                val = match if isinstance(match, str) else match[0] if match else ""
                if val and len(val) > 4:
                    findings["secrets"].append({
                        "type": name,
                        "value": val[:100],
                        "source": url,
                    })

        # Search for endpoints
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                val = match if isinstance(match, str) else match[0] if match else ""
                if val and len(val) > 1:
                    findings["endpoints"].append(val)

    except Exception:
        pass

    return findings


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 8: JS File Analysis & Secret Finding."""
    logger.phase_start(8, "JavaScript Analysis & Secret Finding", "regex scanner")

    urls_file = os.path.join(scan_dir, "all_urls.txt")
    secrets_file = os.path.join(scan_dir, "js_secrets.txt")
    endpoints_file = os.path.join(scan_dir, "js_endpoints.txt")

    if not os.path.isfile(urls_file):
        logger.warning("No URLs file found - skipping JS analysis")
        logger.phase_end(8, "JS Analysis", 0)
        return ""

    js_urls = extract_js_urls(urls_file)
    logger.info(f"Found {len(js_urls)} JS files to analyze")

    # Limit to avoid excessive requests
    js_urls = js_urls[:200]

    all_secrets = []
    all_endpoints = set()

    for i, url in enumerate(js_urls):
        if (i + 1) % 50 == 0:
            logger.info(f"  Analyzed {i + 1}/{len(js_urls)} JS files...")

        findings = scan_js_content(url)
        all_secrets.extend(findings["secrets"])
        all_endpoints.update(findings["endpoints"])

    # Write secrets
    secret_lines = []
    for s in all_secrets:
        secret_lines.append(f"[{s['type']}] {s['value']} (from: {s['source']})")
    write_lines(secrets_file, secret_lines)

    # Write endpoints
    write_lines(endpoints_file, sorted(all_endpoints))

    logger.found_count("secrets/keys", len(all_secrets))
    logger.found_count("endpoints from JS", len(all_endpoints))
    logger.phase_end(8, "JS Analysis", len(all_secrets))
    return secrets_file
