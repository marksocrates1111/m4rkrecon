"""
Phase 20: Report Generation
Generates HTML dashboard + JSON + TXT summary reports.
"""

import os
import json
from datetime import datetime
from core.utils import read_lines, parse_jsonl, read_json, count_results


def gather_scan_data(scan_dir: str, domain: str) -> dict:
    """Gather all scan results into a structured dict."""
    data = {
        "domain": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_dir": scan_dir,
        "subdomains": read_lines(os.path.join(scan_dir, "subdomains.txt")),
        "live_hosts": read_lines(os.path.join(scan_dir, "live_urls.txt")),
        "ports": read_lines(os.path.join(scan_dir, "ports.txt")),
        "urls": read_lines(os.path.join(scan_dir, "all_urls.txt")),
        "js_secrets": read_lines(os.path.join(scan_dir, "js_secrets.txt")),
        "js_endpoints": read_lines(os.path.join(scan_dir, "js_endpoints.txt")),
        "directories": read_lines(os.path.join(scan_dir, "directories.txt")),
        "parameters": read_lines(os.path.join(scan_dir, "parameters.txt")),
        "nuclei_results": read_lines(os.path.join(scan_dir, "nuclei_results.txt")),
        "takeover_results": read_lines(os.path.join(scan_dir, "takeover_results.txt")),
        "xss_results": read_lines(os.path.join(scan_dir, "xss_results.txt")),
        "sqli_results": read_lines(os.path.join(scan_dir, "sqli_results.txt")),
        "cors_results": read_lines(os.path.join(scan_dir, "cors_results.txt")),
        "redirect_results": read_lines(os.path.join(scan_dir, "redirect_results.txt")),
        "ssrf_results": read_lines(os.path.join(scan_dir, "ssrf_results.txt")),
        "ssl_results": read_lines(os.path.join(scan_dir, "ssl_results.txt")),
        "waf_results": read_lines(os.path.join(scan_dir, "waf_results.txt")),
    }

    # Parse nuclei JSON if available
    nuclei_json = os.path.join(scan_dir, "nuclei_results.json")
    if os.path.isfile(nuclei_json):
        entries = parse_jsonl(nuclei_json)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for e in entries:
            sev = e.get("info", {}).get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        data["severity_counts"] = severity_counts
    else:
        data["severity_counts"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # OSINT data
    osint_dir = os.path.join(scan_dir, "phase19_osint")
    whois_file = os.path.join(osint_dir, "whois.json")
    if os.path.isfile(whois_file):
        data["whois"] = read_json(whois_file)
    else:
        data["whois"] = {}

    shodan_file = os.path.join(osint_dir, "shodan.json")
    if os.path.isfile(shodan_file):
        data["shodan"] = read_json(shodan_file)
    else:
        data["shodan"] = {}

    # httpx JSON for technology data
    httpx_json = os.path.join(scan_dir, "httpx_results.json")
    if os.path.isfile(httpx_json):
        entries = parse_jsonl(httpx_json)
        techs = set()
        for e in entries:
            for t in e.get("tech", []):
                techs.add(t)
        data["technologies"] = sorted(techs)
    else:
        data["technologies"] = []

    return data


def generate_txt_report(data: dict, output_file: str):
    """Generate plain text summary report."""
    lines = [
        "=" * 70,
        f"  M4rkRecon Scan Report",
        f"  Target: {data['domain']}",
        f"  Date: {data['scan_date']}",
        "=" * 70,
        "",
        "SUMMARY",
        "-" * 40,
        f"  Subdomains found:      {len(data['subdomains'])}",
        f"  Live hosts:            {len(data['live_hosts'])}",
        f"  Open ports:            {len(data['ports'])}",
        f"  URLs discovered:       {len(data['urls'])}",
        f"  JS Secrets found:      {len(data['js_secrets'])}",
        f"  Directories found:     {len(data['directories'])}",
        f"  Parameters found:      {len(data['parameters'])}",
        "",
        "VULNERABILITIES",
        "-" * 40,
        f"  Nuclei findings:       {len(data['nuclei_results'])}",
        f"    Critical:            {data['severity_counts']['critical']}",
        f"    High:                {data['severity_counts']['high']}",
        f"    Medium:              {data['severity_counts']['medium']}",
        f"    Low:                 {data['severity_counts']['low']}",
        f"    Info:                {data['severity_counts']['info']}",
        f"  XSS vulnerabilities:   {len(data['xss_results'])}",
        f"  SQLi vulnerabilities:  {len(data['sqli_results'])}",
        f"  CORS misconfigs:       {len(data['cors_results'])}",
        f"  Open redirects:        {len(data['redirect_results'])}",
        f"  SSRF candidates:       {len(data['ssrf_results'])}",
        f"  Subdomain takeovers:   {len(data['takeover_results'])}",
        "",
        "TECHNOLOGIES",
        "-" * 40,
    ]

    for tech in data.get("technologies", []):
        lines.append(f"  - {tech}")

    if data.get("whois"):
        lines.extend([
            "",
            "WHOIS",
            "-" * 40,
            f"  Registrar: {data['whois'].get('registrar', 'N/A')}",
            f"  Created: {data['whois'].get('creation_date', 'N/A')}",
            f"  Expires: {data['whois'].get('expiration_date', 'N/A')}",
            f"  Org: {data['whois'].get('org', 'N/A')}",
        ])

    # Top findings
    for section_name, key in [
        ("NUCLEI FINDINGS", "nuclei_results"),
        ("XSS FINDINGS", "xss_results"),
        ("SQLI FINDINGS", "sqli_results"),
        ("JS SECRETS", "js_secrets"),
        ("SUBDOMAIN TAKEOVERS", "takeover_results"),
    ]:
        items = data.get(key, [])
        if items:
            lines.extend(["", section_name, "-" * 40])
            for item in items[:50]:
                lines.append(f"  {item}")

    lines.extend(["", "=" * 70, "  Report generated by M4rkRecon v2.0.0", "=" * 70])

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def generate_json_report(data: dict, output_file: str):
    """Generate JSON report."""
    # Convert lists to counts for summary, keep full data
    report = {
        "meta": {
            "tool": "M4rkRecon",
            "version": "2.0.0",
            "domain": data["domain"],
            "scan_date": data["scan_date"],
        },
        "summary": {
            "subdomains": len(data["subdomains"]),
            "live_hosts": len(data["live_hosts"]),
            "open_ports": len(data["ports"]),
            "urls": len(data["urls"]),
            "js_secrets": len(data["js_secrets"]),
            "vulnerabilities": {
                "nuclei": len(data["nuclei_results"]),
                "xss": len(data["xss_results"]),
                "sqli": len(data["sqli_results"]),
                "cors": len(data["cors_results"]),
                "redirects": len(data["redirect_results"]),
                "ssrf": len(data["ssrf_results"]),
                "takeovers": len(data["takeover_results"]),
            },
            "severity": data["severity_counts"],
        },
        "technologies": data.get("technologies", []),
        "whois": data.get("whois", {}),
        "shodan": data.get("shodan", {}),
        "data": {
            "subdomains": data["subdomains"][:500],
            "live_hosts": data["live_hosts"][:500],
            "nuclei_results": data["nuclei_results"][:200],
            "xss_results": data["xss_results"][:100],
            "sqli_results": data["sqli_results"][:100],
            "js_secrets": data["js_secrets"][:100],
        },
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)


def generate_html_report(data: dict, output_file: str):
    """Generate HTML dashboard report."""
    sev = data["severity_counts"]
    total_vulns = (
        len(data["nuclei_results"])
        + len(data["xss_results"])
        + len(data["sqli_results"])
        + len(data["cors_results"])
        + len(data["redirect_results"])
        + len(data["ssrf_results"])
        + len(data["takeover_results"])
    )

    def make_list_html(items, max_items=100):
        if not items:
            return '<p class="text-muted">No results</p>'
        html = '<div class="results-list">'
        for item in items[:max_items]:
            escaped = str(item).replace("<", "&lt;").replace(">", "&gt;")
            html += f'<div class="result-item">{escaped}</div>'
        if len(items) > max_items:
            html += f'<div class="text-muted">...and {len(items) - max_items} more</div>'
        html += "</div>"
        return html

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>M4rkRecon Report - {data['domain']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0e17;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #0f1923 0%, #1a2332 100%);
            padding: 30px;
            text-align: center;
            border-bottom: 2px solid #00d4ff;
        }}
        .header h1 {{ color: #00d4ff; font-size: 2.5em; margin-bottom: 5px; }}
        .header .subtitle {{ color: #8892a4; font-size: 1.1em; }}
        .header .domain {{ color: #00ff88; font-size: 1.4em; margin-top: 10px; }}
        .header .date {{ color: #5a6577; margin-top: 5px; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 25px 0;
        }}
        .stat-card {{
            background: #141b27;
            border: 1px solid #1e2a3a;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-3px); border-color: #00d4ff; }}
        .stat-card .number {{ font-size: 2.2em; font-weight: bold; color: #00d4ff; }}
        .stat-card .label {{ color: #8892a4; font-size: 0.9em; margin-top: 5px; }}
        .stat-card.critical .number {{ color: #ff4444; }}
        .stat-card.high .number {{ color: #ff8800; }}
        .stat-card.medium .number {{ color: #ffcc00; }}
        .stat-card.low .number {{ color: #44bbff; }}
        .stat-card.info .number {{ color: #00ff88; }}
        .section {{
            background: #141b27;
            border: 1px solid #1e2a3a;
            border-radius: 10px;
            margin: 20px 0;
            overflow: hidden;
        }}
        .section-header {{
            background: #1a2332;
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1e2a3a;
        }}
        .section-header h2 {{ color: #00d4ff; font-size: 1.2em; }}
        .section-header .count {{
            background: #00d4ff22;
            color: #00d4ff;
            padding: 3px 12px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        .section-body {{ padding: 15px 20px; max-height: 500px; overflow-y: auto; }}
        .results-list {{ font-family: 'Courier New', monospace; font-size: 0.85em; }}
        .result-item {{
            padding: 6px 10px;
            border-bottom: 1px solid #1e2a3a11;
            word-break: break-all;
        }}
        .result-item:nth-child(odd) {{ background: #0f1520; }}
        .text-muted {{ color: #5a6577; }}
        .severity-bar {{
            display: flex;
            gap: 10px;
            margin: 20px 0;
            justify-content: center;
        }}
        .sev-badge {{
            padding: 8px 20px;
            border-radius: 8px;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .sev-critical {{ background: #ff444433; color: #ff4444; border: 1px solid #ff4444; }}
        .sev-high {{ background: #ff880033; color: #ff8800; border: 1px solid #ff8800; }}
        .sev-medium {{ background: #ffcc0033; color: #ffcc00; border: 1px solid #ffcc00; }}
        .sev-low {{ background: #44bbff33; color: #44bbff; border: 1px solid #44bbff; }}
        .sev-info {{ background: #00ff8833; color: #00ff88; border: 1px solid #00ff88; }}
        .tech-tags {{ display: flex; flex-wrap: wrap; gap: 8px; padding: 10px; }}
        .tech-tag {{
            background: #00d4ff15;
            border: 1px solid #00d4ff44;
            color: #00d4ff;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.85em;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: #5a6577;
            border-top: 1px solid #1e2a3a;
            margin-top: 30px;
        }}
        .footer a {{ color: #00d4ff; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>M4rkRecon</h1>
        <div class="subtitle">All-in-One Cybersecurity Reconnaissance Report</div>
        <div class="domain">{data['domain']}</div>
        <div class="date">{data['scan_date']}</div>
    </div>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card"><div class="number">{len(data['subdomains'])}</div><div class="label">Subdomains</div></div>
            <div class="stat-card"><div class="number">{len(data['live_hosts'])}</div><div class="label">Live Hosts</div></div>
            <div class="stat-card"><div class="number">{len(data['ports'])}</div><div class="label">Open Ports</div></div>
            <div class="stat-card"><div class="number">{len(data['urls'])}</div><div class="label">URLs Found</div></div>
            <div class="stat-card"><div class="number">{len(data['js_secrets'])}</div><div class="label">JS Secrets</div></div>
            <div class="stat-card critical"><div class="number">{total_vulns}</div><div class="label">Total Vulns</div></div>
        </div>

        <div class="severity-bar">
            <div class="sev-badge sev-critical">Critical: {sev['critical']}</div>
            <div class="sev-badge sev-high">High: {sev['high']}</div>
            <div class="sev-badge sev-medium">Medium: {sev['medium']}</div>
            <div class="sev-badge sev-low">Low: {sev['low']}</div>
            <div class="sev-badge sev-info">Info: {sev['info']}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>Technologies Detected</h2>
                <span class="count">{len(data.get('technologies', []))}</span>
            </div>
            <div class="section-body">
                <div class="tech-tags">
                    {''.join(f'<span class="tech-tag">{t}</span>' for t in data.get('technologies', [])) or '<span class="text-muted">None detected</span>'}
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>Subdomains</h2>
                <span class="count">{len(data['subdomains'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['subdomains'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>Live Hosts</h2>
                <span class="count">{len(data['live_hosts'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['live_hosts'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>Nuclei Findings</h2>
                <span class="count">{len(data['nuclei_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['nuclei_results'], 200)}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>XSS Vulnerabilities</h2>
                <span class="count">{len(data['xss_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['xss_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>SQL Injection</h2>
                <span class="count">{len(data['sqli_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['sqli_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>JS Secrets &amp; API Keys</h2>
                <span class="count">{len(data['js_secrets'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['js_secrets'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>CORS Misconfigurations</h2>
                <span class="count">{len(data['cors_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['cors_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>Open Redirects</h2>
                <span class="count">{len(data['redirect_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['redirect_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>SSRF Candidates</h2>
                <span class="count">{len(data['ssrf_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['ssrf_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>Subdomain Takeovers</h2>
                <span class="count">{len(data['takeover_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['takeover_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>WAF Detection</h2>
                <span class="count">{len(data['waf_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['waf_results'])}</div>
        </div>

        <div class="section">
            <div class="section-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
                <h2>SSL/TLS Analysis</h2>
                <span class="count">{len(data['ssl_results'])}</span>
            </div>
            <div class="section-body">{make_list_html(data['ssl_results'])}</div>
        </div>
    </div>

    <div class="footer">
        <p>Generated by <strong>M4rkRecon v2.0.0</strong> | by MarkSocrates</p>
        <p>35+ tools | 20 phases | All-in-One Reconnaissance Framework</p>
    </div>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 20: Report Generation."""
    logger.phase_start(20, "Report Generation", "HTML + JSON + TXT")

    data = gather_scan_data(scan_dir, domain)

    # Generate all report formats
    txt_file = os.path.join(scan_dir, "report.txt")
    json_file = os.path.join(scan_dir, "report.json")
    html_file = os.path.join(scan_dir, "report.html")

    generate_txt_report(data, txt_file)
    logger.info(f"TXT report: {txt_file}")

    generate_json_report(data, json_file)
    logger.info(f"JSON report: {json_file}")

    generate_html_report(data, html_file)
    logger.info(f"HTML report: {html_file}")

    logger.phase_end(20, "Report Generation", 3)
    return html_file
