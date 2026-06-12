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


def version_in_range(prod_version: str, vrange: dict) -> bool | None:
    """
    Evaluate a cvelistV5-style version range object against the product version.
    Returns True/False, or None if it can't be determined (=> needs review).

    vrange examples:
      {"version": "7.2.4", "status": "affected"}
      {"version": "7.0.0", "lessThan": "7.2.5", "status": "affected"}
      {"version": "0", "lessThanOrEqual": "9.2", "status": "affected"}
    """
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
        verdicts = [version_in_range(product.version, vr) for vr in versions]
        if any(v is True for v in verdicts) and vendor_ok:
            return Match(
                "medium",
                f"vendor+product token match, version {product.version} in affected range",
            )

        # 3) product matched but version inconclusive/absent -> low (review)
        # Keep as a candidate; don't return yet in case a better aff entry exists.
        if vendor_ok:
            cand = Match(
                "low",
                f"product '{aff.get('product','')}' matched; version unverified — review",
            )
            best = best or cand

    return best
