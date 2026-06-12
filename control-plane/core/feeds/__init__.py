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
import gzip
import io
import json
import os
from pathlib import Path

FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "cvelist_raw": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main",
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

    # Reference URLs — vendor advisories, patches, mitigations. The best
    # remediation pointers we have; surface them on findings.
    refs = []
    for src in (cna, *adps):
        for r in src.get("references", []) or []:
            url = r.get("url", "")
            if url and url not in refs:
                refs.append(url)

    return {
        "cve_id": meta.get("cveId", ""),
        "title": cna.get("title", "")[:500],
        "summary": summary,
        "cvss": cvss,
        "cwe": cwe,
        "affected": affected,
        "references": refs[:12],
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


# ---- live fetchers (used on the deployed box) -----------------------------
#
# cvelistV5 is a ~2GB git repo, so we DON'T clone it. Instead we fetch the
# recent-activity delta plus individual CVE records straight from raw GitHub by
# constructing their path. That keeps the pull light and incremental:
#   CVE-2024-21887 -> cves/2024/21xxx/CVE-2024-21887.json
# The actionable set each night is: everything in KEV (exploited) + everything
# newly published/updated (the delta). Historical backfill is a separate job.

def _get(url, timeout=30):
    import requests
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "recon-feed/0.1"})
    r.raise_for_status()
    return r


def fetch_kev() -> dict[str, str]:
    """CISA KEV -> {cve_id: dateAdded}."""
    data = _get(FEEDS["kev"]).json()
    return {v["cveID"]: v.get("dateAdded") for v in data.get("vulnerabilities", [])}


def fetch_epss() -> dict[str, float]:
    """EPSS gzipped CSV -> {cve_id: score}."""
    raw = gzip.decompress(_get(FEEDS["epss"], timeout=90).content)
    return parse_epss(raw)


def fetch_delta_ids() -> set[str]:
    """Recently published/updated CVE ids from cvelistV5 cves/delta.json."""
    delta = _get(f"{FEEDS['cvelist_raw']}/cves/delta.json").json()
    ids = set()
    for bucket in ("new", "updated"):
        for item in delta.get(bucket, []) or []:
            cid = item.get("cveId") or item.get("cveID")
            if cid:
                ids.add(cid)
    return ids


def cvelist_path(cve_id: str) -> str:
    """Construct the raw-GitHub path for a CVE record."""
    _, year, num = cve_id.split("-")
    bucket = f"{int(num) // 1000}xxx"
    return f"{FEEDS['cvelist_raw']}/cves/{year}/{bucket}/{cve_id}.json"


def fetch_cve_record(cve_id: str) -> dict | None:
    """Fetch + flatten one cvelistV5 record. Returns None if absent/withdrawn."""
    try:
        rec = _get(cvelist_path(cve_id), timeout=20).json()
    except Exception:
        return None
    return parse_cve_record(rec)


def assemble_live(delta_limit: int = 800) -> dict:
    """
    Build the actionable CVE set from live feeds: KEV (always) + recent delta
    (capped). Each record is enriched with its KEV flag/date and EPSS score.
    Per-record failures are skipped, not fatal.
    """
    kev = fetch_kev()
    epss = fetch_epss()

    target = set(kev)
    delta = fetch_delta_ids()
    target |= set(list(delta)[:delta_limit])

    cves = {}
    for cid in target:
        flat = fetch_cve_record(cid)
        if not flat:
            continue
        flat["in_kev"] = cid in kev
        flat["kev_date_added"] = kev.get(cid)
        flat["epss"] = epss.get(cid)
        cves[cid] = flat
    return {"cves": cves, "kev": kev, "epss": epss}


# ---- local cvelistV5 mirror (preferred on the box) ------------------------
#
# Mirror the cvelistV5 repo to a persistent volume once, then `git pull` nightly
# for deltas (small). Reading records off local disk is instant and hits no rate
# limits — far better than thousands of per-record GitHub requests. KEV and EPSS
# stay as small direct downloads; only the bulky CVE corpus is mirrored.

CVELIST_DIR = os.environ.get("CVELIST_DIR", "/data/cvelist")
CVELIST_REPO = "https://github.com/CVEProject/cvelistV5"


def mirror_present() -> bool:
    return Path(CVELIST_DIR, "cves").is_dir()


def local_cve_path(cve_id: str) -> Path:
    _, year, num = cve_id.split("-")
    bucket = f"{int(num) // 1000}xxx"
    return Path(CVELIST_DIR, "cves", year, bucket, f"{cve_id}.json")


def read_local_cve(cve_id: str) -> dict | None:
    p = local_cve_path(cve_id)
    if not p.is_file():
        return None
    try:
        return parse_cve_record(json.loads(p.read_text()))
    except Exception:
        return None


def read_local_delta() -> set[str]:
    """Recently changed CVE ids from the mirror's cves/delta.json."""
    p = Path(CVELIST_DIR, "cves", "delta.json")
    if not p.is_file():
        return set()
    try:
        delta = json.loads(p.read_text())
    except Exception:
        return set()
    ids = set()
    for bucket in ("new", "updated"):
        for item in delta.get(bucket, []) or []:
            cid = item.get("cveId") or item.get("cveID")
            if cid:
                ids.add(cid)
    return ids


def assemble_local() -> dict:
    """
    Same actionable set as assemble_live (KEV + recent delta), but the CVE
    records are read from the local mirror instead of fetched over HTTP.
    """
    kev = fetch_kev()
    epss = fetch_epss()

    target = set(kev) | read_local_delta()
    cves = {}
    for cid in target:
        flat = read_local_cve(cid)
        if not flat:
            continue
        flat["in_kev"] = cid in kev
        flat["kev_date_added"] = kev.get(cid)
        flat["epss"] = epss.get(cid)
        cves[cid] = flat
    return {"cves": cves, "kev": kev, "epss": epss}


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
