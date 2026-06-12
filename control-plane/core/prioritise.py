"""
Prioritisation (§5.4).

Do NOT rank by CVSS alone — it's noisy and, per the OIG, now unreliable.
Exploitation-led order:

    in KEV?                      -> P1  (being exploited right now)
    high EPSS + internet-facing  -> P2  (likely to be, and reachable)
    high EPSS  OR  internet-facing high-CVSS -> P3
    everything else              -> P4
    low-confidence match         -> P?  (human review, regardless of score)

This is what makes the output actionable instead of a 4,000-row CSV nobody reads.
"""

EPSS_HIGH = 0.30   # tune against real data; 0.3 is a reasonable "pay attention" line
CVSS_HIGH = 7.0


def prioritise(cve, asset, match_confidence: str) -> str:
    """Return a Finding.Priority value."""
    # Weak matches always go to a human first — never auto-escalate a maybe.
    if match_confidence == "low":
        return "P?"

    if cve.in_kev:
        return "P1"

    epss = cve.epss or 0.0
    facing = bool(asset.internet_facing)
    cvss = cve.cvss or 0.0

    if epss >= EPSS_HIGH and facing:
        return "P2"
    if epss >= EPSS_HIGH or (facing and cvss >= CVSS_HIGH):
        return "P3"
    return "P4"
