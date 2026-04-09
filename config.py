"""
M4rkRecon - Configuration
All tool paths, API keys, wordlists, and tuning parameters.
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")

# ── Discord Webhook ──────────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = os.environ.get(
    "M4RKRECON_DISCORD_WEBHOOK",
    "https://discord.com/api/webhooks/1491485330505990351/8hfJUYUspmf4WmAPzt_DyQY76_FVgPY7GTphfv6Y4xiUIvPRR9aJRP__D8YiE8HVFWiA",
)

# ── API Keys (set via environment variables) ──────────────────────────────
API_KEYS = {
    "shodan": os.environ.get("SHODAN_API_KEY", ""),
    "censys_pat": os.environ.get("CENSYS_PAT", ""),
    # Legacy Censys (deprecated, kept for backwards compat)
    "censys_id": os.environ.get("CENSYS_API_ID", ""),
    "censys_secret": os.environ.get("CENSYS_API_SECRET", ""),
    "virustotal": os.environ.get("VT_API_KEY", ""),
    "securitytrails": os.environ.get("SECURITYTRAILS_API_KEY", ""),
}

# ── Default wordlists ────────────────────────────────────────────────────
WORDLISTS = {
    "subdomains": os.path.join(WORDLIST_DIR, "subdomains.txt"),
    "directories": os.path.join(WORDLIST_DIR, "directories.txt"),
    "parameters": os.path.join(WORDLIST_DIR, "parameters.txt"),
}

# ── Performance tuning (VPS-optimized defaults) ──────────────────────────
THREADS = 50
RATE_LIMIT = 150          # requests/sec for httpx, nuclei, etc.
PORT_RATE = 5000           # packets/sec for naabu
TIMEOUT = 10               # seconds per request
DNS_RESOLVERS = os.path.join(WORDLIST_DIR, "resolvers.txt")

# ── Nuclei settings ─────────────────────────────────────────────────────
NUCLEI_SEVERITY = "info,low,medium,high,critical"
NUCLEI_TEMPLATES_EXCLUDE = ["dos", "fuzzing"]

# ── Scan profiles ────────────────────────────────────────────────────────
PROFILES = {
    "fast": {
        "description": "Quick passive recon only",
        "phases": [1, 3, 4, 5, 18, 19, 20],
    },
    "standard": {
        "description": "Full recon + vuln scan (no active exploitation)",
        "phases": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 18, 19, 20],
    },
    "full": {
        "description": "Everything including XSS, SQLi, SSRF, CORS, redirects",
        "phases": list(range(1, 21)),
    },
    "stealth": {
        "description": "Passive only - no active probing",
        "phases": [1, 3, 19, 20],
    },
}

# ── Tool binary resolution ───────────────────────────────────────────────
def find_tool(name):
    """Find a tool binary in PATH or common locations."""
    path = shutil.which(name)
    if path:
        return path
    common_paths = [
        os.path.expanduser(f"~/go/bin/{name}"),
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
        f"/snap/bin/{name}",
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return p
    return name  # fallback to name, will fail at runtime if not found


TOOLS = {
    "subfinder": find_tool("subfinder"),
    "amass": find_tool("amass"),
    "assetfinder": find_tool("assetfinder"),
    "shuffledns": find_tool("shuffledns"),
    "dnsx": find_tool("dnsx"),
    "httpx": find_tool("httpx"),
    "naabu": find_tool("naabu"),
    "nmap": find_tool("nmap"),
    "masscan": find_tool("masscan"),
    "katana": find_tool("katana"),
    "waybackurls": find_tool("waybackurls"),
    "gau": find_tool("gau"),
    "nuclei": find_tool("nuclei"),
    "subjack": find_tool("subjack"),
    "subzy": find_tool("subzy"),
    "dalfox": find_tool("dalfox"),
    "ffuf": find_tool("ffuf"),
    "dirsearch": find_tool("dirsearch"),
    "feroxbuster": find_tool("feroxbuster"),
    "arjun": find_tool("arjun"),
    "paramspider": find_tool("paramspider"),
    "sqlmap": find_tool("sqlmap"),
    "ghauri": find_tool("ghauri"),
    "wafw00f": find_tool("wafw00f"),
    "whatwaf": find_tool("whatwaf"),
    "tlsx": find_tool("tlsx"),
    "sslscan": find_tool("sslscan"),
    "theHarvester": find_tool("theHarvester"),
    "secretfinder": find_tool("SecretFinder.py"),
    "linkfinder": find_tool("linkfinder"),
    "corsy": find_tool("corsy"),
    "openredirex": find_tool("openredirex"),
    "oralyzer": find_tool("oralyzer"),
    "ssrfmap": find_tool("ssrfmap"),
    "kxss": find_tool("kxss"),
    "uro": find_tool("uro"),
    "qsreplace": find_tool("qsreplace"),
}
