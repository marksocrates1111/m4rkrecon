"""
Phase 19: OSINT / WHOIS / Shodan Enrichment
Tools: theHarvester, whois, Shodan API, Censys API
"""

import os
import json
import socket
import subprocess
from core.runner import run_command, tool_exists
from core.utils import read_lines, write_lines, write_json
from config import TOOLS, API_KEYS


def run_theharvester(domain: str, output_file: str, logger) -> str:
    """Run theHarvester for email/subdomain/IP gathering."""
    tool = TOOLS["theHarvester"]
    if not tool_exists(tool):
        logger.tool_not_found("theHarvester")
        return ""

    logger.info("Running theHarvester...")
    cmd = [
        tool,
        "-d", domain,
        "-l", "500",
        "-b", "all",
        "-f", output_file,
    ]
    rc, stdout, stderr = run_command(cmd, timeout=300)

    if stdout:
        logger.info(f"theHarvester completed")
    return stdout


def run_whois(domain: str, output_file: str, logger) -> dict:
    """Run WHOIS lookup."""
    logger.info(f"Running WHOIS for {domain}...")
    try:
        import whois
        w = whois.whois(domain)
        info = {
            "domain_name": str(w.domain_name) if w.domain_name else "",
            "registrar": str(w.registrar) if w.registrar else "",
            "creation_date": str(w.creation_date) if w.creation_date else "",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "",
            "name_servers": [str(ns) for ns in w.name_servers] if w.name_servers else [],
            "org": str(w.org) if w.org else "",
            "country": str(w.country) if w.country else "",
            "emails": list(w.emails) if w.emails else [],
        }
        write_json(output_file, info)
        logger.info(f"  Registrar: {info['registrar']}")
        logger.info(f"  Created: {info['creation_date']}")
        logger.info(f"  Org: {info['org']}")
        return info
    except Exception as e:
        logger.warning(f"WHOIS error: {e}")
        # Fallback to system whois command
        try:
            rc, stdout, stderr = run_command(["whois", domain], timeout=30)
            if stdout:
                with open(output_file.replace(".json", ".txt"), "w") as f:
                    f.write(stdout)
            return {}
        except Exception:
            return {}


def run_shodan(domain: str, output_file: str, logger) -> dict:
    """Query Shodan API for IP information."""
    api_key = API_KEYS.get("shodan", "")
    if not api_key:
        logger.info("Shodan API key not set - skipping (set SHODAN_API_KEY)")
        return {}

    logger.info("Querying Shodan...")
    try:
        import shodan
        api = shodan.Shodan(api_key)

        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        logger.info(f"  Resolved {domain} -> {ip}")

        # Search Shodan
        host = api.host(ip)
        info = {
            "ip": host.get("ip_str", ""),
            "org": host.get("org", ""),
            "os": host.get("os", ""),
            "ports": host.get("ports", []),
            "vulns": host.get("vulns", []),
            "isp": host.get("isp", ""),
            "country": host.get("country_name", ""),
            "city": host.get("city", ""),
            "hostnames": host.get("hostnames", []),
        }
        write_json(output_file, info)

        logger.info(f"  Org: {info['org']}")
        logger.info(f"  ISP: {info['isp']}")
        logger.info(f"  Open ports: {info['ports']}")
        if info["vulns"]:
            logger.warning(f"  Known CVEs: {', '.join(info['vulns'][:10])}")

        return info

    except Exception as e:
        logger.warning(f"Shodan error: {e}")
        return {}


def run_censys(domain: str, output_file: str, logger) -> dict:
    """Query Censys Platform API for host information using Personal Access Token."""
    import requests as req

    pat = API_KEYS.get("censys_pat", "")

    # Fallback: try legacy API ID/Secret if no PAT
    if not pat:
        api_id = API_KEYS.get("censys_id", "")
        api_secret = API_KEYS.get("censys_secret", "")
        if api_id and api_secret:
            return _run_censys_legacy(domain, output_file, logger, api_id, api_secret)
        logger.info("Censys PAT not set - skipping (set CENSYS_PAT env var)")
        return {}

    logger.info("Querying Censys Platform API...")
    try:
        # Resolve domain to IP
        ip = socket.gethostbyname(domain)
        logger.info(f"  Resolved {domain} -> {ip}")

        # Censys Platform API v3 - host lookup
        url = f"https://api.platform.censys.io/v3/hosts/{ip}"
        headers = {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/json",
        }
        resp = req.get(url, headers=headers, timeout=15)

        if resp.status_code == 401:
            logger.warning("Censys: authentication failed - check your PAT")
            return {}
        if resp.status_code == 403:
            logger.warning("Censys: access denied - your plan may not include this endpoint")
            return {}
        if resp.status_code == 429:
            logger.warning("Censys: rate limited - try again later")
            return {}
        if resp.status_code != 200:
            logger.warning(f"Censys: API returned status {resp.status_code}")
            return {}

        data = resp.json()
        host = data.get("result", data)

        info = {
            "ip": ip,
            "services": [],
            "location": host.get("location", {}),
            "autonomous_system": host.get("autonomous_system", {}),
            "operating_system": host.get("operating_system", {}),
            "last_updated": host.get("last_updated_at", ""),
            "dns": host.get("dns", {}),
        }

        for service in host.get("services", []):
            svc = {
                "port": service.get("port", ""),
                "service_name": service.get("service_name", ""),
                "transport_protocol": service.get("transport_protocol", ""),
                "software": [],
                "certificate": "",
            }
            # Extract software info if available
            for sw in service.get("software", []):
                name = sw.get("product", sw.get("vendor", ""))
                ver = sw.get("version", "")
                if name:
                    svc["software"].append(f"{name} {ver}".strip())
            # TLS certificate
            tls = service.get("tls", {})
            if tls:
                cert = tls.get("certificates", {}).get("leaf", {})
                svc["certificate"] = cert.get("subject_dn", "")
            info["services"].append(svc)

        write_json(output_file, info)

        # Log summary
        logger.info(f"  Services found: {len(info['services'])}")
        for svc in info["services"][:10]:
            sw_str = f" [{', '.join(svc['software'])}]" if svc["software"] else ""
            logger.info(f"    {svc['port']}/{svc['transport_protocol']} - {svc['service_name']}{sw_str}")

        loc = info.get("location", {})
        if loc:
            city = loc.get("city", "")
            country = loc.get("country", "")
            if city or country:
                logger.info(f"  Location: {city}, {country}")

        asn = info.get("autonomous_system", {})
        if asn:
            logger.info(f"  ASN: {asn.get('asn', '')} - {asn.get('name', '')}")

        return info

    except socket.gaierror:
        logger.warning(f"Censys: could not resolve {domain}")
        return {}
    except Exception as e:
        logger.warning(f"Censys error: {e}")
        return {}


def _run_censys_legacy(domain: str, output_file: str, logger, api_id: str, api_secret: str) -> dict:
    """Fallback: Query Censys using legacy API ID/Secret (deprecated)."""
    logger.info("Querying Censys (legacy API)...")
    try:
        from censys.search import CensysHosts
        h = CensysHosts(api_id=api_id, api_secret=api_secret)

        ip = socket.gethostbyname(domain)
        host = h.view(ip)

        info = {
            "ip": ip,
            "services": [],
            "location": host.get("location", {}),
            "autonomous_system": host.get("autonomous_system", {}),
        }
        for service in host.get("services", []):
            info["services"].append({
                "port": service.get("port", ""),
                "service_name": service.get("service_name", ""),
                "transport_protocol": service.get("transport_protocol", ""),
            })

        write_json(output_file, info)
        logger.info(f"  Services: {len(info['services'])}")
        return info

    except Exception as e:
        logger.warning(f"Censys legacy error: {e}")
        return {}


def run_dns_info(domain: str, output_file: str, logger) -> dict:
    """Gather comprehensive DNS information."""
    logger.info("Gathering DNS records...")
    dns_info = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    for rtype in record_types:
        try:
            rc, stdout, stderr = run_command(
                ["nslookup", "-type=" + rtype, domain],
                timeout=10,
            )
            if stdout:
                dns_info[rtype] = stdout
        except Exception:
            continue

    write_json(output_file, dns_info)
    return dns_info


def run_phase(domain: str, scan_dir: str, logger) -> str:
    """Run Phase 19: OSINT Enrichment."""
    logger.phase_start(19, "OSINT / WHOIS / Shodan Enrichment", "theHarvester + WHOIS + Shodan + Censys")

    phase_dir = os.path.join(scan_dir, "phase19_osint")
    os.makedirs(phase_dir, exist_ok=True)

    # theHarvester
    harvester_file = os.path.join(phase_dir, "theharvester")
    run_theharvester(domain, harvester_file, logger)

    # WHOIS
    whois_file = os.path.join(phase_dir, "whois.json")
    run_whois(domain, whois_file, logger)

    # DNS
    dns_file = os.path.join(phase_dir, "dns_records.json")
    run_dns_info(domain, dns_file, logger)

    # Shodan
    shodan_file = os.path.join(phase_dir, "shodan.json")
    run_shodan(domain, shodan_file, logger)

    # Censys
    censys_file = os.path.join(phase_dir, "censys.json")
    run_censys(domain, censys_file, logger)

    logger.phase_end(19, "OSINT Enrichment", 1)
    return phase_dir
