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
from functools import lru_cache

# ----- normalisation -------------------------------------------------------

_NOISE = re.compile(
    r"\b(\d{2,4}-bit|x64|x86|amd64|inc|ltd|corp|corporation|software|the|llc|gmbh)\b",
    re.I,
)
_NONWORD = re.compile(r"[^a-z0-9]+")


@lru_cache(maxsize=200_000)
def normalise(s: str) -> str:
    """Lowercase, strip vendor noise, collapse to spaced tokens.

    Memoised: called millions of times across a match run on a bounded set of
    distinct strings (product names + corpus affected-product names). The regex
    work dominated runtime before this cache.
    """
    if not s:
        return ""
    s = s.lower()
    s = _NOISE.sub(" ", s)
    s = _NONWORD.sub(" ", s)
    return " ".join(s.split())


@lru_cache(maxsize=200_000)
def tokens(s: str) -> frozenset[str]:
    return frozenset(normalise(s).split())


# Generic vendor / filler words that must NOT, on their own, constitute a
# product match. Without this, "Microsoft Edge" matches "Microsoft SharePoint"
# CVEs because they share "microsoft". Product-identifying tokens (office, edge,
# sharepoint, acrobat, chrome, tomcat…) are deliberately NOT here.
STOPWORDS = {
    "microsoft", "apple", "google", "adobe", "oracle", "apache", "mozilla",
    "ibm", "cisco", "intel", "amd", "nvidia", "vmware", "citrix", "sap",
    "symantec", "mcafee", "dell", "lenovo", "hp", "hewlett", "packard",
    "corporation", "corp", "inc", "incorporated", "ltd", "limited", "llc",
    "gmbh", "co", "company", "software", "systems", "technologies",
    "technology", "solutions", "group", "the", "for", "and", "of",
    "version", "update", "updates", "edition", "professional", "enterprise",
    "standard", "server", "client", "tools", "runtime", "redistributable",
    "win", "win32", "win64",
    # Generic platform / component / wrapper words. These are common across many
    # different product names, so on their own they must NOT anchor a match —
    # otherwise every "Windows ..." app matches every Windows CVE, every "... Agent"
    # matches every agent CVE, etc. (the cause of the false-positive pile-up). Real
    # product names survive because their distinctive token remains (e.g. "Zabbix
    # Agent" -> {zabbix}, "Dell Display Manager" -> {display}).
    "windows", "desktop", "agent", "manager", "component", "components",
    "core", "framework", "host", "driver", "drivers", "module", "modules",
    "plugin", "plugins", "extension", "extensions", "feature", "features",
    "helper", "assistant", "installation", "installer", "package", "packages",
    "pack", "based", "service", "services", "x64", "x86", "amd64", "arm64",
    "bit", "kb", "based", "framework", "hub", "hubs", "tools", "toolkit",
}

# Platform qualifiers. If a CVE's affected product names one of these and the
# installed product doesn't, they're different builds (this inventory is all
# Windows agents, so a "... for Mac" CVE matching a Windows install is a certain
# false positive). Matched against full tokens(), not candidate_tokens.
_PLATFORM_TOKENS = frozenset({
    "mac", "macos", "osx", "macintosh", "android", "ios", "iphone", "ipad",
    "ipados", "tvos", "watchos", "linux", "unix", "ubuntu", "debian", "redhat",
    "fedora", "suse", "solaris", "freebsd",
})


@lru_cache(maxsize=200_000)
def candidate_tokens(s: str) -> frozenset[str]:
    """Distinctive, indexable tokens for a name: drop stopwords, pure-numbers,
    and 1-char tokens. Used for CVE candidate selection and the match gate."""
    return frozenset(t for t in tokens(s)
                     if len(t) > 1 and not t.isdigit() and t not in STOPWORDS)


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

@lru_cache(maxsize=200_000)
def _parse_version(v: str):
    """
    Tolerant version parse. Vendor version strings are a swamp ('28.1',
    '7.2.4', '2024.003.20180', 'v1.2-rc1'), so we extract the leading numeric
    dotted run and compare as an int tuple. Returns None if unparseable.

    Rejects strings that are sentences or lists rather than versions — CVE bounds
    like 'OMS Agent for Linux GA v1.13.40-0' or 'DSC Agent versions: 2.71.1.25,
    2.70.0.30, 3.0.0.3' would otherwise yield a stray number and a nonsense compare.
    """
    if not v:
        return None
    s = str(v).strip()
    # A real version has no embedded spaces, commas, colons or semicolons.
    if any(ch in s for ch in (" ", ",", ":", ";")):
        return None
    m = re.search(r"(\d+(?:\.\d+){0,4})", s)
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


_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}:\d{2}:\d{2}|\d{1,2}/\d{1,2}/\d{2,4}")


def _is_date_like(v: str) -> bool:
    """A 'version' that's really a date/timestamp (e.g. '2022-12-02 19:42:16' or
    '04/27/2012') must not be compared as a version — it produces nonsense."""
    return bool(_DATE_RE.search(str(v or "")))


def _major_scheme(v) -> str:
    """Rough version-numbering 'scheme' by the magnitude of the leading component.
    Year-style schemes (Adobe '2020.013.x', SolarWinds '2017.x') carry a 4-digit
    year as the major; short-major schemes (Acrobat '26.x', Chrome '121') don't.
    Comparing across the two is meaningless — '2020' is a bigger number than '26'
    but an OLDER release — so a mismatch means we can't compare."""
    return "year" if v and v[0] >= 1000 else "short"


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
    # Commit hashes and dates aren't comparable software versions. Linux kernel
    # CVEs use git hashes; some appliance/router CVEs use date "versions" like
    # "241108" — comparing an app's 1.3.1 against those is nonsense.
    if (vrange.get("versionType") or "").lower() in ("git", "date"):
        return None
    pv = _parse_version(prod_version)
    if pv is None:
        return None

    lt = _parse_version(vrange.get("lessThan", ""))
    lte = _parse_version(vrange.get("lessThanOrEqual", ""))
    base = _parse_version(vrange.get("version", ""))

    # Year-track vs short-major guard. If the product version and any bound sit on
    # opposite sides of the year threshold (e.g. Acrobat device 26.001 vs an
    # affected bound of 2020.013), they're different numbering schemes and a tuple
    # compare lies (26 < 2020 -> "vulnerable" when 26.x is actually newer).
    for b in (lt, lte, base):
        if b is not None and _major_scheme(pv) != _major_scheme(b):
            return None

    # Cross-scheme guard: catch ranges where the source dropped a prefix from the
    # upper bound — e.g. lower "16.0.0" but upper "5215.1000" (should have been
    # 16.0.5215.1000). The tell is an upper bound with FEWER components than the
    # lower AND a different leading number, which makes a tuple compare nonsense.
    # (Legit single-scheme ranges like Chrome "118 -> 121" are same-length and
    # pass through.)
    upper = lt if lt is not None else lte
    if (base is not None and upper is not None
            and len(base) > len(upper) and base[0] != upper[0]):
        return None

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

        # The product names must share a DISTINCTIVE token (not just a vendor word
        # like "microsoft"), or it isn't really the same product.
        if not (candidate_tokens(product.name) & candidate_tokens(aff.get("product", ""))):
            continue

        # Platform guard: a CVE for "... for Mac"/Android/iOS/Linux must not match a
        # product that doesn't itself name that platform.
        a_plat = a_product_t & _PLATFORM_TOKENS
        if a_plat and not (a_plat & p_name_t):
            continue

        vendor_ok = bool(p_vendor_t & a_vendor_t) or not (p_vendor_t and a_vendor_t)

        # 2) version-range path -> medium
        versions = aff.get("versions") or []
        matched_range = None
        any_inconclusive = False
        for vr in versions:
            r = version_in_range(product.version, vr)
            if r is True:
                matched_range = vr
                break
            if r is None:
                any_inconclusive = True
        if matched_range is not None and vendor_ok:
            installed = (product.name or "this software").strip()
            aff_name = (aff.get("product") or "").strip()
            # Name what's ACTUALLY on the device, not the advisory's product name —
            # and when the advisory calls it something different (shared vendor /
            # category word, e.g. installed 'Web Components' vs advisory 'Sophos Web
            # Appliance'), say so, so a coincidental match is obvious to verify.
            extra = ""
            if aff_name and normalise(aff_name) != normalise(installed):
                extra = f", matched against the advisory's \u201c{aff_name}\u201d"
            return Match(
                "medium",
                f"This device runs {installed} {product.version}, which is in the "
                f"affected range ({_describe_range(matched_range)}){extra} for this CVE.",
            )

        # 3) product name matched but the version was NOT confirmed in range.
        # Recon only raises a finding when it can confirm exposure — a version
        # provably in the affected range (medium) or a CPE match (high). A bare
        # name match with an unconfirmable version is not actionable and was the
        # single largest source of false positives, so it is NOT a finding.
        continue

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
