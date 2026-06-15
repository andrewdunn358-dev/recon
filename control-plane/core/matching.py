"""
Product x CVE matching — the core IP (§6: "the valuable join").

Design constraint that drives everything here: as of the NVD triage change
(§5.1), ~80% of new CVEs ship WITHOUT clean CPE data. A matcher that only does
CPE comparison would silently miss most of what's published. So we do:

    1. CPE match           -> high confidence   (when both sides have a CPE)
    2. vendor+product+ver  -> medium confidence  (token match + version in range)
    3. vendor+product only -> low confidence     (no usable version data => review)

Low-confidence matches are NOT dropped and NOT auto-fired — they become
P?-priority findings flagged for a logged-in human (§4.3 advisory-only posture).
Better a human glances at a maybe than the loop silently misses a live CVE.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ----- normalisation -------------------------------------------------------

_NOISE = re.compile(
    r"\b(\d{2,4}-bit|x64|x86|amd64|inc|ltd|corp|corporation|software|the|llc|gmbh)\b",
    re.I,
)
_NONWORD = re.compile(r"[^a-z0-9]+")


def normalise(s: str) -> str:
    """Lowercase, strip vendor noise, collapse to spaced tokens."""
    if not s:
        return ""
    s = s.lower()
    s = _NOISE.sub(" ", s)
    s = _NONWORD.sub(" ", s)
    return " ".join(s.split())


def tokens(s: str) -> set[str]:
    return set(normalise(s).split())


def affected_product_tokens(affected) -> set[str]:
    """
    Every distinct normalised product token across a CVE's affected[] entries.
    This is exactly the left side of the matcher's `p_name_t & a_product_t` gate,
    so indexing these tokens lets us pre-select the same candidates by overlap.
    """
    toks: set[str] = set()
    for aff in affected or []:
        toks |= tokens(aff.get("product", ""))
    # Drop pure-numeric and 1-char tokens — too noisy to index usefully.
    return {t for t in toks if len(t) > 1 and not t.isdigit()}


# ----- version handling ----------------------------------------------------

def _parse_version(v: str):
    """
    Tolerant version parse. Vendor version strings are a swamp ('28.1',
    '7.2.4', '2024.003.20180', 'v1.2-rc1'), so we extract the leading numeric
    dotted run and compare as an int tuple. Returns None if unparseable.
    """
    if not v:
        return None
    m = re.search(r"(\d+(?:\.\d+){0,4})", str(v))
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _cmp(a, b) -> int:
    """Compare two parsed version tuples, padding the shorter with zeros."""
    if a is None or b is None:
        return 0  # unknown — treat as inconclusive
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}:\d{2}")


def _is_date_like(v: str) -> bool:
    """A 'version' that's really a date/timestamp (e.g. '2022-12-02 19:42:16')
    must not be compared as a version — it produces nonsense matches."""
    return bool(_DATE_RE.search(str(v or "")))


def version_in_range(prod_version: str, vrange: dict) -> bool | None:
    """
    Evaluate a cvelistV5-style version range object against the product version.
    Returns True/False, or None if it can't be determined (=> needs review).

    vrange examples:
      {"version": "7.2.4", "status": "affected"}
      {"version": "7.0.0", "lessThan": "7.2.5", "status": "affected"}
      {"version": "0", "lessThanOrEqual": "9.2", "status": "affected"}
    """
    if _is_date_like(prod_version):
        return None  # not a real version — don't claim a confident match
    pv = _parse_version(prod_version)
    if pv is None:
        return None

    lt = _parse_version(vrange.get("lessThan", ""))
    lte = _parse_version(vrange.get("lessThanOrEqual", ""))
    base = _parse_version(vrange.get("version", ""))

    # Exact-version statement with no range.
    if base is not None and lt is None and lte is None:
        return _cmp(pv, base) == 0

    lower_ok = True if base is None else _cmp(pv, base) >= 0
    upper_ok = True
    if lt is not None:
        upper_ok = _cmp(pv, lt) < 0
    elif lte is not None:
        upper_ok = _cmp(pv, lte) <= 0

    if base is None and lt is None and lte is None:
        return None
    return lower_ok and upper_ok


# ----- the matcher ---------------------------------------------------------

@dataclass
class Match:
    confidence: str   # high / medium / low
    reason: str


def _cpe_match(product_cpe: str, affected: dict) -> Match | None:
    """High-confidence path: both sides carry a CPE."""
    acpe = (affected.get("cpe") or "").lower()
    pcpe = (product_cpe or "").lower()
    if not acpe or not pcpe:
        return None
    # Compare the vendor:product portion of CPE 2.3 (parts 3,4,5).
    p = pcpe.split(":")
    a = acpe.split(":")
    if len(p) >= 5 and len(a) >= 5 and p[3:5] == a[3:5]:
        return Match("high", f"CPE vendor:product match ({a[3]}:{a[4]})")
    return None


def match_product_to_cve(product, cve) -> Match | None:
    """
    Try to match one Product against one CVE record.
    Returns the best Match found, or None if nothing plausible.
    """
    p_vendor_t = tokens(product.vendor)
    p_name_t = tokens(product.name)

    best: Match | None = None

    for aff in cve.affected or []:
        # 1) CPE path
        if product.cpe:
            m = _cpe_match(product.cpe, aff)
            if m:
                return m  # high confidence, can't do better

        a_vendor_t = tokens(aff.get("vendor", ""))
        a_product_t = tokens(aff.get("product", ""))

        # Product name must overlap to be worth considering at all.
        if not (p_name_t & a_product_t):
            continue

        vendor_ok = bool(p_vendor_t & a_vendor_t) or not (p_vendor_t and a_vendor_t)

        # 2) version-range path -> medium
        versions = aff.get("versions") or []
        matched_range = None
        for vr in versions:
            if version_in_range(product.version, vr) is True:
                matched_range = vr
                break
        if matched_range is not None and vendor_ok:
            who = (aff.get("product") or "this software").strip()
            return Match(
                "medium",
                f"This device runs {who} {product.version}, which is in the "
                f"affected range ({_describe_range(matched_range)}) for this CVE.",
            )

        # 3) product matched but version inconclusive/absent -> low (review)
        # Keep as a candidate; don't return yet in case a better aff entry exists.
        if vendor_ok:
            who = (aff.get("product") or "this software").strip()
            cand = Match(
                "low",
                f"This device runs {who}, which this CVE affects, but the version "
                f"couldn't be confirmed against the affected range — needs review.",
            )
            best = best or cand

    return best


def _describe_range(vr: dict) -> str:
    """Human phrasing of a cvelistV5 version-range object."""
    base = (vr.get("version") or "").strip()
    lt = (vr.get("lessThan") or "").strip()
    lte = (vr.get("lessThanOrEqual") or "").strip()
    if lt and base and base not in ("0", "*"):
        return f"{base} up to but not including {lt}"
    if lt:
        return f"before {lt}"
    if lte and base and base not in ("0", "*"):
        return f"{base} up to and including {lte}"
    if lte:
        return f"up to and including {lte}"
    if base and base not in ("0", "*"):
        return f"version {base}"
    return "all versions"
