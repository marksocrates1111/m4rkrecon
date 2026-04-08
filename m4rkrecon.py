#!/usr/bin/env python3
"""
M4rkRecon v2.0.0 - All-in-One Cybersecurity Reconnaissance Framework
by MarkSocrates

Usage:
    python3 m4rkrecon.py                          # Interactive mode
    python3 m4rkrecon.py -d example.com           # Direct target
    python3 m4rkrecon.py -d example.com -p full   # Full profile
    python3 m4rkrecon.py -d example.com --skip-sqli --skip-xss
"""

import sys
import os
import argparse
import time
import warnings
from datetime import datetime

# Suppress SSL warnings for recon
warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore:Unverified HTTPS request"

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import OUTPUT_DIR, PROFILES, DISCORD_WEBHOOK_URL
from core.banner import print_banner
from core.logger import M4rkLogger, console
from core.utils import validate_domain, create_scan_dir, read_lines
from core.discord import DiscordNotifier

# Import all phase modules
from modules import subdomain_enum      # Phase 1
from modules import subdomain_brute     # Phase 2
from modules import dns_resolve         # Phase 3
from modules import live_hosts          # Phase 4
from modules import waf_detect          # Phase 5
from modules import port_scan           # Phase 6
from modules import web_crawl           # Phase 7
from modules import js_secrets          # Phase 8
from modules import dir_bruteforce      # Phase 9
from modules import param_discovery     # Phase 10
from modules import vuln_scan           # Phase 11
from modules import subdomain_takeover  # Phase 12
from modules import xss_scan            # Phase 13
from modules import sqli_scan           # Phase 14
from modules import cors_scan           # Phase 15
from modules import open_redirect       # Phase 16
from modules import ssrf_scan           # Phase 17
from modules import ssl_scan            # Phase 18
from modules import osint_recon         # Phase 19
from reports import generator           # Phase 20


# Map phase numbers to modules and names
PHASE_MAP = {
    1:  ("Subdomain Enumeration",      subdomain_enum),
    2:  ("Subdomain Bruteforce",       subdomain_brute),
    3:  ("DNS Resolution",             dns_resolve),
    4:  ("Live Host Detection",        live_hosts),
    5:  ("WAF Detection",              waf_detect),
    6:  ("Port Scanning",              port_scan),
    7:  ("Web Crawling & URLs",        web_crawl),
    8:  ("JS Secret Finding",          js_secrets),
    9:  ("Directory Bruteforce",       dir_bruteforce),
    10: ("Parameter Discovery",        param_discovery),
    11: ("Vulnerability Scan (Nuclei)", vuln_scan),
    12: ("Subdomain Takeover",         subdomain_takeover),
    13: ("XSS Scanning",              xss_scan),
    14: ("SQL Injection Testing",      sqli_scan),
    15: ("CORS Misconfiguration",      cors_scan),
    16: ("Open Redirect Detection",    open_redirect),
    17: ("SSRF Detection",            ssrf_scan),
    18: ("SSL/TLS Analysis",          ssl_scan),
    19: ("OSINT Enrichment",          osint_recon),
    20: ("Report Generation",          generator),
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="M4rkRecon v2.0.0 - All-in-One Cybersecurity Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Profiles:
  fast      Quick passive recon only (phases 1,3,4,5,18,19,20)
  standard  Full recon + vuln scan, no active exploitation (default)
  full      Everything including XSS, SQLi, SSRF, CORS, redirects
  stealth   Passive only - no active probing (phases 1,3,19,20)

Examples:
  python3 m4rkrecon.py -d example.com
  python3 m4rkrecon.py -d example.com -p full
  python3 m4rkrecon.py -d example.com --skip-sqli --skip-xss
  python3 m4rkrecon.py -d example.com --phases 1,4,11,20
        """,
    )
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-p", "--profile", default="standard",
                        choices=["fast", "standard", "full", "stealth"],
                        help="Scan profile (default: standard)")
    parser.add_argument("-o", "--output", default=OUTPUT_DIR,
                        help="Output directory")
    parser.add_argument("--phases", help="Run specific phases (comma-separated, e.g., 1,4,11,20)")

    # Skip flags
    parser.add_argument("--skip-brute", action="store_true", help="Skip subdomain bruteforce")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-crawl", action="store_true", help="Skip web crawling")
    parser.add_argument("--skip-dirs", action="store_true", help="Skip directory bruteforce")
    parser.add_argument("--skip-params", action="store_true", help="Skip parameter discovery")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip nuclei scan")
    parser.add_argument("--skip-xss", action="store_true", help="Skip XSS scanning")
    parser.add_argument("--skip-sqli", action="store_true", help="Skip SQL injection testing")
    parser.add_argument("--skip-cors", action="store_true", help="Skip CORS scan")
    parser.add_argument("--skip-redirect", action="store_true", help="Skip open redirect detection")
    parser.add_argument("--skip-ssrf", action="store_true", help="Skip SSRF detection")
    parser.add_argument("--skip-ssl", action="store_true", help="Skip SSL/TLS analysis")
    parser.add_argument("--skip-osint", action="store_true", help="Skip OSINT enrichment")
    parser.add_argument("--skip-waf", action="store_true", help="Skip WAF detection")
    parser.add_argument("--skip-takeover", action="store_true", help="Skip subdomain takeover check")
    parser.add_argument("--skip-js", action="store_true", help="Skip JS secret analysis")

    # Discord
    parser.add_argument("--no-discord", action="store_true", help="Disable Discord notifications")
    parser.add_argument("--discord-webhook", default="",
                        help="Override Discord webhook URL")

    return parser.parse_args()


SKIP_FLAG_MAP = {
    2: "skip_brute",
    5: "skip_waf",
    6: "skip_ports",
    7: "skip_crawl",
    8: "skip_js",
    9: "skip_dirs",
    10: "skip_params",
    11: "skip_nuclei",
    12: "skip_takeover",
    13: "skip_xss",
    14: "skip_sqli",
    15: "skip_cors",
    16: "skip_redirect",
    17: "skip_ssrf",
    18: "skip_ssl",
    19: "skip_osint",
}


def get_phases_to_run(args) -> list[int]:
    """Determine which phases to run based on profile, flags, and explicit selection."""
    # If explicit phases specified, use those
    if args.phases:
        phases = [int(p.strip()) for p in args.phases.split(",")]
        return sorted(phases)

    # Get phases from profile
    profile = PROFILES.get(args.profile, PROFILES["standard"])
    phases = list(profile["phases"])

    # Remove skipped phases
    for phase_num, flag_name in SKIP_FLAG_MAP.items():
        if getattr(args, flag_name, False) and phase_num in phases:
            phases.remove(phase_num)

    # Always include report generation
    if 20 not in phases:
        phases.append(20)

    return sorted(phases)


def run_scan(domain: str, args):
    """Execute the full reconnaissance pipeline."""
    start_time = time.time()

    # Create output directory
    scan_dir = create_scan_dir(args.output, domain)
    logger = M4rkLogger(scan_dir)

    phases = get_phases_to_run(args)
    profile = PROFILES.get(args.profile, PROFILES["standard"])

    # ── Initialize Discord ───────────────────────────────────────────
    webhook_url = args.discord_webhook or DISCORD_WEBHOOK_URL
    discord = DiscordNotifier(
        webhook_url=webhook_url,
        enabled=not args.no_discord,
    )

    logger.separator()
    logger.info(f"Target:      {domain}")
    logger.info(f"Profile:     {args.profile} - {profile['description']}")
    logger.info(f"Phases:      {', '.join(str(p) for p in phases)}")
    logger.info(f"Output:      {scan_dir}")
    if discord.enabled:
        logger.info("Discord:     notifications enabled")
    logger.separator()
    console.print()

    # Notify Discord: scan started
    discord.notify_scan_start(domain, args.profile, phases, scan_dir)

    # Execute each phase
    for phase_num in phases:
        if phase_num not in PHASE_MAP:
            logger.warning(f"Unknown phase {phase_num} - skipping")
            continue

        phase_name, module = PHASE_MAP[phase_num]
        discord.notify_phase_start(phase_num, phase_name)

        try:
            module.run_phase(domain, scan_dir, logger)
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            discord.send_embed(
                title="Scan Interrupted",
                description=f"Scan on `{domain}` was interrupted by user. Generating partial report...",
                color=discord.COLOR_WARNING,
            )
            logger.info("Generating partial report...")
            try:
                generator.run_phase(domain, scan_dir, logger)
            except Exception:
                pass
            break
        except Exception as e:
            logger.error(f"Phase {phase_num} ({phase_name}) failed: {e}")
            discord.notify_phase_error(phase_num, phase_name, str(e))
            continue

        # ── Post-phase Discord alerts for significant findings ───────
        _send_phase_alerts(phase_num, scan_dir, discord, logger)

    # ── Final summary ────────────────────────────────────────────────
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    duration_str = f"{minutes}m {seconds}s"

    logger.separator()
    console.print()
    console.print(f"  [bold green]Scan complete![/] Duration: {duration_str}")
    console.print(f"  [bold white]Results:[/] {scan_dir}")
    console.print(f"  [bold white]Report:[/]  {os.path.join(scan_dir, 'report.html')}")
    console.print()
    logger.separator()

    # ── Discord: send final report ───────────────────────────────────
    from reports.generator import gather_scan_data
    scan_data = gather_scan_data(scan_dir, domain)
    discord.notify_scan_complete(scan_data, duration_str)

    # Upload the JSON report file to Discord
    json_report = os.path.join(scan_dir, "report.json")
    txt_report = os.path.join(scan_dir, "report.txt")
    if discord.upload_report_file(json_report):
        logger.info("Discord: JSON report uploaded")
    if discord.upload_report_file(txt_report):
        logger.info("Discord: TXT report uploaded")


def _send_phase_alerts(phase_num: int, scan_dir: str, discord: DiscordNotifier, logger):
    """Send Discord alerts after specific phases if significant findings exist."""
    if not discord.enabled:
        return

    try:
        if phase_num == 1:
            # Subdomain count
            subs = read_lines(os.path.join(scan_dir, "subdomains.txt"))
            discord.notify_phase_end(1, "Subdomain Enumeration", len(subs))

        elif phase_num == 4:
            # Live hosts count
            hosts = read_lines(os.path.join(scan_dir, "live_urls.txt"))
            discord.notify_phase_end(4, "Live Host Detection", len(hosts))

        elif phase_num == 6:
            # Ports
            ports = read_lines(os.path.join(scan_dir, "ports.txt"))
            discord.notify_phase_end(6, "Port Scanning", len(ports))

        elif phase_num == 8:
            # JS secrets - always significant
            secrets = read_lines(os.path.join(scan_dir, "js_secrets.txt"))
            if secrets:
                discord.notify_secrets_found(secrets)

        elif phase_num == 11:
            # Nuclei findings - alert on critical/high
            results = read_lines(os.path.join(scan_dir, "nuclei_results.txt"))
            discord.notify_phase_end(11, "Vulnerability Scan", len(results))
            for r in results:
                if "critical" in r.lower():
                    discord.notify_critical_vuln(r, "nuclei")

        elif phase_num == 12:
            # Subdomain takeovers
            findings = read_lines(os.path.join(scan_dir, "takeover_results.txt"))
            discord.notify_takeover(findings)

        elif phase_num == 13:
            # XSS
            findings = read_lines(os.path.join(scan_dir, "xss_results.txt"))
            discord.notify_xss_found(findings)

        elif phase_num == 14:
            # SQLi
            findings = read_lines(os.path.join(scan_dir, "sqli_results.txt"))
            discord.notify_sqli_found(findings)

        elif phase_num == 15:
            # CORS
            findings = read_lines(os.path.join(scan_dir, "cors_results.txt"))
            discord.notify_cors_found(findings)

    except Exception:
        pass  # Never let Discord errors interrupt the scan


def main():
    print_banner()
    args = parse_args()

    # Get domain
    domain = args.domain
    if not domain:
        try:
            console.print("  [bold cyan]Enter target domain[/]")
            domain = input("\n  Target domain: ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [dim]Exiting...[/]")
            sys.exit(0)

    if not domain:
        console.print("  [error]No domain provided[/]")
        sys.exit(1)

    # Clean domain input
    domain = domain.lower().strip()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    if not validate_domain(domain):
        console.print(f"  [error]Invalid domain format: {domain}[/]")
        sys.exit(1)

    console.print(f"\n  [bold green]Target locked:[/] {domain}\n")

    # Confirm before starting
    try:
        confirm = input("  Start scan? [Y/n]: ").strip().lower()
        if confirm and confirm != "y":
            console.print("  [dim]Scan cancelled.[/]")
            sys.exit(0)
    except (KeyboardInterrupt, EOFError):
        console.print("\n  [dim]Exiting...[/]")
        sys.exit(0)

    console.print()
    run_scan(domain, args)


if __name__ == "__main__":
    main()
