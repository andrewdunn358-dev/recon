"""
Multi-source feed ingestion (§5.2).

Single-source NVD would silently miss most of what's published post-triage
(§5.1), so we assemble each CVE from several feeds:

    CISA KEV          -> in_kev flag        (exploited right now; alert first)
    EPSS (FIRST.org)  -> epss score         (rank everything not in KEV)
    MITRE cvelistV5   -> raw record         (canonical now NVD is triage-only)
    CISA Vulnrichment -> SSVC/CWE/CVSS       (backfills what NVD no longer scores)
    Google OSV        -> OSS/dependency CVEs

Real source URLs live in FEEDS below — they work on your box where cisa.gov /
first.org are reachable. In the sandbox those domains aren't allowlisted, so
load_fixtures() seeds the same shapes from core/fixtures/ to prove the loop.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "cvelist": "https://github.com/CVEProject/cvelistV5",  # cloned/pulled, not fetched whole
    "osv": "https://api.osv.dev/v1/query",
}

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"


# ---- real-feed parsers (used on the deployed box) -------------------------

def parse_kev(raw: bytes) -> set[str]:
    """CISA KEV JSON -> set of CVE IDs currently in the catalogue."""
    data = json.loads(raw)
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def parse_epss(raw: bytes) -> dict[str, float]:
    """EPSS CSV (gunzipped upstream) -> {cve_id: score}."""
    text = raw.decode("utf-8", "replace")
    out: dict[str, float] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#") or row[0] == "cve":
            continue
        try:
            out[row[0]] = float(row[1])
        except (IndexError, ValueError):
            continue
    return out


def parse_cve_record(record: dict) -> dict:
    """
    Flatten a cvelistV5 v5.x record (+ Vulnrichment ADP container) into the
    shape core.models.CVE expects. Tolerant of the metadata gaps that are now
    the norm.
    """
    meta = record.get("cveMetadata", {})
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    adps = containers.get("adp", []) or []

    affected = []
    for a in cna.get("affected", []) or []:
        affected.append({
            "vendor": a.get("vendor", ""),
            "product": a.get("product", ""),
            "cpe": (a.get("cpes") or [""])[0],
            "versions": a.get("versions", []) or [],
        })

    # Pull CVSS/CWE from CNA first, then Vulnrichment ADP if CNA is bare.
    cvss = _first_cvss(cna)
    cwe = _first_cwe(cna)
    for adp in adps:
        cvss = cvss or _first_cvss(adp)
        cwe = cwe or _first_cwe(adp)

    descs = cna.get("descriptions", [])
    summary = next((d.get("value", "") for d in descs if d.get("lang", "").startswith("en")), "")

    return {
        "cve_id": meta.get("cveId", ""),
        "title": cna.get("title", "")[:500],
        "summary": summary,
        "cvss": cvss,
        "cwe": cwe,
        "affected": affected,
        "sources": ["cvelistV5"],
        "published": (meta.get("datePublished") or "")[:10] or None,
    }


def _first_cvss(container: dict):
    for m in container.get("metrics", []) or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in m and "baseScore" in m[key]:
                return float(m[key]["baseScore"])
    return None


def _first_cwe(container: dict):
    for pt in container.get("problemTypes", []) or []:
        for d in pt.get("descriptions", []) or []:
            if d.get("cweId"):
                return d["cweId"]
    return ""


# ---- offline fixtures (used in the sandbox / CI) --------------------------

def load_fixtures() -> dict:
    """
    Load the same data shapes from core/fixtures/ so the watch loop can be
    proven without reaching cisa.gov / first.org. Returns assembled CVE dicts
    keyed by id, plus kev set and epss map.
    """
    kev = set(json.loads((FIXTURE_DIR / "kev.json").read_text())["cveID_list"])
    epss = json.loads((FIXTURE_DIR / "epss.json").read_text())
    records = json.loads((FIXTURE_DIR / "cvelist.json").read_text())

    cves = {}
    for rec in records:
        flat = parse_cve_record(rec)
        cid = flat["cve_id"]
        flat["in_kev"] = cid in kev
        flat["epss"] = epss.get(cid)
        cves[cid] = flat
    return {"cves": cves, "kev": kev, "epss": epss}
