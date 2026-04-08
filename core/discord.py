"""
M4rkRecon - Discord Webhook Notifications
Sends scan progress, significant findings, and final reports to Discord.
"""

import os
import json
import time
import requests
from datetime import datetime


class DiscordNotifier:
    """Sends rich embed notifications to a Discord webhook."""

    # Colors for embed sidebar
    COLOR_INFO    = 0x00D4FF   # cyan
    COLOR_SUCCESS = 0x00FF88   # green
    COLOR_WARNING = 0xFFCC00   # yellow
    COLOR_DANGER  = 0xFF4444   # red
    COLOR_ORANGE  = 0xFF8800   # orange
    COLOR_PURPLE  = 0xAA55FF   # purple

    def __init__(self, webhook_url: str, enabled: bool = True):
        self.webhook_url = webhook_url
        self.enabled = enabled and bool(webhook_url)
        self.domain = ""
        self.scan_dir = ""
        self._rate_limit_until = 0

    def _send(self, payload: dict) -> bool:
        """Send a payload to the Discord webhook with rate-limit handling."""
        if not self.enabled:
            return False

        # Respect rate limits
        now = time.time()
        if now < self._rate_limit_until:
            time.sleep(self._rate_limit_until - now)

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            # Handle rate limiting
            if resp.status_code == 429:
                retry_after = resp.json().get("retry_after", 2)
                self._rate_limit_until = time.time() + retry_after
                time.sleep(retry_after)
                resp = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

            return resp.status_code in (200, 204)
        except Exception:
            return False

    def send_embed(self, title: str, description: str, color: int = None,
                   fields: list = None, footer: str = None, thumbnail: str = None) -> bool:
        """Send a rich embed message."""
        embed = {
            "title": title[:256],
            "description": description[:4096],
            "color": color or self.COLOR_INFO,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if fields:
            embed["fields"] = fields[:25]
        if footer:
            embed["footer"] = {"text": footer[:2048]}
        else:
            embed["footer"] = {"text": "M4rkRecon v2.0.0 | by MarkSocrates"}
        if thumbnail:
            embed["thumbnail"] = {"url": thumbnail}

        return self._send({"embeds": [embed]})

    def send_message(self, content: str) -> bool:
        """Send a plain text message."""
        return self._send({"content": content[:2000]})

    # ── Scan lifecycle notifications ─────────────────────────────────────

    def notify_scan_start(self, domain: str, profile: str, phases: list, scan_dir: str):
        """Notify that a scan has started."""
        self.domain = domain
        self.scan_dir = scan_dir

        phase_str = ", ".join(str(p) for p in phases)
        self.send_embed(
            title="Scan Started",
            description=f"**Target:** `{domain}`",
            color=self.COLOR_INFO,
            fields=[
                {"name": "Profile", "value": f"`{profile}`", "inline": True},
                {"name": "Phases", "value": f"`{phase_str}`", "inline": True},
                {"name": "Output", "value": f"```{scan_dir}```", "inline": False},
            ],
        )

    def notify_phase_start(self, phase_num: int, phase_name: str):
        """Notify that a phase has started (only for key phases)."""
        # Only notify for major phases to avoid spam
        key_phases = {1, 4, 6, 11, 13, 14, 20}
        if phase_num not in key_phases:
            return
        self.send_embed(
            title=f"Phase {phase_num}: {phase_name}",
            description=f"Starting phase {phase_num} on `{self.domain}`...",
            color=self.COLOR_INFO,
        )

    def notify_phase_end(self, phase_num: int, phase_name: str, count: int):
        """Notify phase completion with result count."""
        # Only notify if there are meaningful results
        if count == 0:
            return
        color = self.COLOR_SUCCESS
        self.send_embed(
            title=f"Phase {phase_num} Complete: {phase_name}",
            description=f"Found **{count}** results for `{self.domain}`",
            color=color,
        )

    def notify_phase_error(self, phase_num: int, phase_name: str, error: str):
        """Notify that a phase failed."""
        self.send_embed(
            title=f"Phase {phase_num} Failed: {phase_name}",
            description=f"```{error[:500]}```",
            color=self.COLOR_DANGER,
        )

    # ── Significant finding notifications ────────────────────────────────

    def notify_critical_vuln(self, finding: str, source: str = "nuclei"):
        """Immediately notify about critical/high severity vulnerabilities."""
        self.send_embed(
            title="CRITICAL Vulnerability Found",
            description=f"```\n{finding[:1000]}\n```",
            color=self.COLOR_DANGER,
            fields=[
                {"name": "Target", "value": f"`{self.domain}`", "inline": True},
                {"name": "Source", "value": f"`{source}`", "inline": True},
            ],
        )

    def notify_secrets_found(self, secrets: list):
        """Notify about discovered secrets/API keys."""
        if not secrets:
            return
        # Truncate each secret value for safety
        lines = []
        for s in secrets[:15]:
            safe = s[:120] + "..." if len(s) > 120 else s
            lines.append(safe)
        secret_text = "\n".join(lines)

        self.send_embed(
            title=f"JS Secrets Found ({len(secrets)} total)",
            description=f"```\n{secret_text[:3500]}\n```",
            color=self.COLOR_ORANGE,
            fields=[
                {"name": "Target", "value": f"`{self.domain}`", "inline": True},
            ],
        )

    def notify_takeover(self, findings: list):
        """Notify about subdomain takeover possibilities."""
        if not findings:
            return
        text = "\n".join(findings[:20])
        self.send_embed(
            title=f"Subdomain Takeover Candidates ({len(findings)})",
            description=f"```\n{text[:3500]}\n```",
            color=self.COLOR_DANGER,
        )

    def notify_xss_found(self, findings: list):
        """Notify about XSS vulnerabilities."""
        if not findings:
            return
        text = "\n".join(findings[:15])
        self.send_embed(
            title=f"XSS Vulnerabilities Found ({len(findings)})",
            description=f"```\n{text[:3500]}\n```",
            color=self.COLOR_DANGER,
        )

    def notify_sqli_found(self, findings: list):
        """Notify about SQL injection vulnerabilities."""
        if not findings:
            return
        text = "\n".join(findings[:15])
        self.send_embed(
            title=f"SQL Injection Found ({len(findings)})",
            description=f"```\n{text[:3500]}\n```",
            color=self.COLOR_DANGER,
        )

    def notify_cors_found(self, findings: list):
        """Notify about CORS misconfigurations."""
        if not findings:
            return
        text = "\n".join(findings[:15])
        self.send_embed(
            title=f"CORS Misconfigurations ({len(findings)})",
            description=f"```\n{text[:3500]}\n```",
            color=self.COLOR_ORANGE,
        )

    # ── Final report notification ────────────────────────────────────────

    def notify_scan_complete(self, data: dict, duration_str: str):
        """Send the final scan summary to Discord."""
        sev = data.get("severity_counts", {})
        total_vulns = (
            len(data.get("nuclei_results", []))
            + len(data.get("xss_results", []))
            + len(data.get("sqli_results", []))
            + len(data.get("cors_results", []))
            + len(data.get("redirect_results", []))
            + len(data.get("ssrf_results", []))
            + len(data.get("takeover_results", []))
        )

        # Determine overall severity color
        if sev.get("critical", 0) > 0 or len(data.get("sqli_results", [])) > 0:
            color = self.COLOR_DANGER
        elif sev.get("high", 0) > 0 or len(data.get("xss_results", [])) > 0:
            color = self.COLOR_ORANGE
        elif total_vulns > 0:
            color = self.COLOR_WARNING
        else:
            color = self.COLOR_SUCCESS

        # Build fields
        fields = [
            {"name": "Subdomains", "value": f"`{len(data.get('subdomains', []))}`", "inline": True},
            {"name": "Live Hosts", "value": f"`{len(data.get('live_hosts', []))}`", "inline": True},
            {"name": "Open Ports", "value": f"`{len(data.get('ports', []))}`", "inline": True},
            {"name": "URLs", "value": f"`{len(data.get('urls', []))}`", "inline": True},
            {"name": "JS Secrets", "value": f"`{len(data.get('js_secrets', []))}`", "inline": True},
            {"name": "Total Vulns", "value": f"`{total_vulns}`", "inline": True},
        ]

        # Severity breakdown
        sev_line = (
            f"Critical: **{sev.get('critical', 0)}** | "
            f"High: **{sev.get('high', 0)}** | "
            f"Medium: **{sev.get('medium', 0)}** | "
            f"Low: **{sev.get('low', 0)}** | "
            f"Info: **{sev.get('info', 0)}**"
        )
        fields.append({"name": "Nuclei Severity Breakdown", "value": sev_line, "inline": False})

        # Vuln detail fields
        vuln_fields = [
            ("XSS", "xss_results"),
            ("SQLi", "sqli_results"),
            ("CORS", "cors_results"),
            ("Open Redirects", "redirect_results"),
            ("SSRF", "ssrf_results"),
            ("Takeovers", "takeover_results"),
        ]
        vuln_parts = []
        for label, key in vuln_fields:
            count = len(data.get(key, []))
            if count > 0:
                vuln_parts.append(f"**{label}:** {count}")
        if vuln_parts:
            fields.append({"name": "Vulnerability Details", "value": " | ".join(vuln_parts), "inline": False})

        # Technologies
        techs = data.get("technologies", [])
        if techs:
            tech_str = ", ".join(f"`{t}`" for t in techs[:20])
            if len(techs) > 20:
                tech_str += f" +{len(techs) - 20} more"
            fields.append({"name": "Technologies", "value": tech_str, "inline": False})

        fields.append({"name": "Duration", "value": f"`{duration_str}`", "inline": True})
        fields.append({"name": "Output Dir", "value": f"```{data.get('scan_dir', 'N/A')}```", "inline": False})

        self.send_embed(
            title=f"Scan Complete: {data.get('domain', self.domain)}",
            description=f"Full reconnaissance scan finished for **{data.get('domain', self.domain)}**",
            color=color,
            fields=fields[:25],
            footer=f"M4rkRecon v2.0.0 | {data.get('scan_date', '')}",
        )

        # If there are critical findings, send a separate alert
        critical_items = []
        for result in data.get("nuclei_results", []):
            if "critical" in result.lower():
                critical_items.append(result)
        for result in data.get("sqli_results", []):
            critical_items.append(result)
        for result in data.get("takeover_results", []):
            critical_items.append(result)

        if critical_items:
            text = "\n".join(critical_items[:25])
            self.send_embed(
                title=f"ALERT: Critical Findings for {self.domain}",
                description=f"```\n{text[:3500]}\n```",
                color=self.COLOR_DANGER,
            )

    def upload_report_file(self, filepath: str):
        """Upload the JSON or TXT report file to Discord (max 25MB)."""
        if not self.enabled or not os.path.isfile(filepath):
            return False

        file_size = os.path.getsize(filepath)
        if file_size > 25 * 1024 * 1024:  # 25MB limit
            return False
        if file_size == 0:
            return False

        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                resp = requests.post(
                    self.webhook_url,
                    files={"file": (filename, f)},
                    data={"content": f"**M4rkRecon Report** - `{self.domain}`"},
                    timeout=30,
                )
            return resp.status_code in (200, 204)
        except Exception:
            return False
