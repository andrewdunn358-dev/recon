"""
External attack-surface discovery (Step 1). Agentless: enumerate subdomains,
probe which are live, fingerprint the tech stack — feeding Assets and Products
into the same Product×CVE matcher used for agent inventory.

Chain (ProjectDiscovery): subfinder -> httpx -> naabu. Each emits JSONL; the
parsers below turn that into plain dicts the ingest step maps onto the models.
Nothing here decides authorisation — the task does, gated on scanning_authorised
(§11). These functions are pure (no DB, no network) so they're unit-testable
without the binaries present.
"""
from __future__ import annotations

import ipaddress
import json


def looks_like_ip(s: str) -> bool:
    """True for a bare IPv4/IPv6 (optionally with /CIDR)."""
    try:
        ipaddress.ip_address(s.split("/")[0].strip())
        return True
    except ValueError:
        return False


def _lines(stdout: str):
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            yield line


def parse_subfinder(stdout: str) -> list[str]:
    """
    subfinder output. With -json each line is an object with a 'host'; with plain
    -silent each line is a bare hostname. Handle both.
    """
    hosts = []
    for line in _lines(stdout):
        try:
            obj = json.loads(line)
            h = obj.get("host") or obj.get("input")
            if h:
                hosts.append(h)
        except ValueError:
            hosts.append(line)
    return sorted(set(hosts))


def parse_httpx(stdout: str) -> list[dict]:
    """
    httpx -json: one live web endpoint per line, with fingerprint fields. We keep
    url/host/port/status/title/webserver and the detected tech list.
    """
    out = []
    for line in _lines(stdout):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        out.append({
            "url": o.get("url", ""),
            "host": o.get("host") or o.get("input", ""),
            "port": str(o.get("port", "")),
            "status": o.get("status_code"),
            "title": o.get("title", ""),
            "webserver": o.get("webserver", ""),
            "tech": list(o.get("tech") or o.get("technologies") or []),
        })
    return out


def parse_naabu(stdout: str) -> dict[str, list[int]]:
    """naabu -json: {host/ip, port} lines. Returns host -> sorted open ports."""
    ports: dict[str, list[int]] = {}
    for line in _lines(stdout):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        host = o.get("host") or o.get("ip")
        p = o.get("port")
        if host and p:
            ports.setdefault(host, []).append(int(p))
    return {h: sorted(set(v)) for h, v in ports.items()}


# httpx/Wappalyzer tech names -> a vendor hint for common products. The matcher
# tolerates a blank vendor (it has a product-token path), but a hint lifts a
# match from low to medium confidence, so it's worth seeding the obvious ones.
VENDOR_HINTS = {
    "tomcat": "apache",
    "httpd": "apache",
    "apache": "apache",
    "nginx": "nginx",
    "openssl": "openssl",
    "microsoft-iis": "microsoft",
    "iis": "microsoft",
    "asp.net": "microsoft",
    "php": "php",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "jquery": "jquery",
    "openssh": "openbsd",
    "exim": "exim",
    "postfix": "postfix",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "atlassian": "atlassian",
    "jira": "atlassian",
    "confluence": "atlassian",
}


def split_tech(tech: str) -> dict:
    """
    Turn an httpx tech/webserver string into vendor/name/version. Tech-detect
    uses a colon ('Apache Tomcat:9.0.1'); the Server header uses a slash
    ('Apache/2.4.52', 'nginx/1.18.0'). Handle both; bare names have no version.
    """
    sep = ":" if ":" in tech else ("/" if "/" in tech else "")
    if sep:
        name, _, version = tech.partition(sep)
    else:
        name, version = tech, ""
    name = name.strip()
    version = version.strip()
    low = name.lower()
    vendor = ""
    for key, v in VENDOR_HINTS.items():
        if key in low:
            vendor = v
            break
    return {"vendor": vendor, "name": name, "version": version}
