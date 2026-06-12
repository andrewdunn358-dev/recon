"""
Nightly orchestration (§7), as Celery tasks.

    feed_pull   -> refresh KEV/EPSS/cvelistV5/Vulnrichment/OSV
    watch_loop  -> Product x CVE match -> prioritise -> raise Findings -> notify
    nuclei_scan -> active scan a tenant's authorised assets (Phase 0 = external)

The watch_loop is the thing Phase 0 must prove: "new CVE -> matched to a
product I run -> alert". It works against the fixture feed in the sandbox and
against the real feeds on your box.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from celery import shared_task
from django.utils import timezone

from . import feeds
from .matching import match_product_to_cve
from .prioritise import prioritise


@shared_task
def feed_pull(use_fixtures: bool = False):
    """
    Refresh the CVE store from the multi-source feed mix. In the sandbox call
    with use_fixtures=True; in production leave it False to hit the real feeds.
    """
    from .models import CVE

    if use_fixtures:
        bundle = feeds.load_fixtures()
        assembled = bundle["cves"]
    else:
        # Live: KEV + EPSS + cvelistV5 deltas, fetched from the real feeds.
        bundle = feeds.assemble_live()
        assembled = bundle["cves"]

    n = 0
    for cid, flat in assembled.items():
        CVE.objects.update_or_create(
            cve_id=cid,
            defaults={
                "title": flat.get("title", ""),
                "summary": flat.get("summary", ""),
                "in_kev": flat.get("in_kev", False),
                "kev_date_added": flat.get("kev_date_added"),
                "epss": flat.get("epss"),
                "cvss": flat.get("cvss"),
                "cwe": flat.get("cwe", ""),
                "affected": flat.get("affected", []),
                "sources": flat.get("sources", []),
                "published": flat.get("published"),
                "last_modified": timezone.now(),
            },
        )
        n += 1
    return f"feed_pull: upserted {n} CVEs ({'fixtures' if use_fixtures else 'live'})"


@shared_task
def watch_loop():
    """
    The core loop. For every product each tenant runs, look for matching CVEs,
    prioritise, and raise/refresh a Finding. Returns a summary string.
    """
    from .models import Product, CVE, Finding

    raised, refreshed = 0, 0
    cves = list(CVE.objects.all())

    for product in Product.objects.select_related("asset", "asset__tenant"):
        asset = product.asset
        for cve in cves:
            m = match_product_to_cve(product, cve)
            if not m:
                continue
            priority = prioritise(cve, asset, m.confidence)
            finding, created = Finding.objects.update_or_create(
                asset=asset, cve=cve, product=product,
                defaults={
                    "tenant": asset.tenant,
                    "priority": priority,
                    "match_confidence": m.confidence,
                    "match_reason": m.reason,
                    "last_seen": timezone.now(),
                },
            )
            if created:
                raised += 1
            else:
                refreshed += 1

    notify_new_findings.delay()
    return f"watch_loop: {raised} new, {refreshed} refreshed"


@shared_task
def notify_new_findings():
    """
    Surface un-notified findings (§7.5). Stub: logs to stdout. On your box wire
    this to email/webhook and optional Zammad ticket creation (Phase 3).
    Advisory only — never triggers remediation (§4.3, §11).
    """
    from .models import Finding

    pending = Finding.objects.filter(notified=False).select_related("cve", "asset", "tenant")
    for f in pending:
        print(f"[ALERT] {f.tenant.name}: {f.cve_id} on {f.asset.name} "
              f"-> {f.get_priority_display()} ({f.match_confidence}: {f.match_reason})")
    count = pending.update(notified=True)
    return f"notify: {count} findings notified"


SEVERITY_TO_PRIORITY = {
    "critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4",
}


@shared_task
def nuclei_scan(tenant_id: int):
    """
    Active external scan with Nuclei against a tenant's authorised assets.
    Phase 0 = external only. Hard-gated on tenant.scanning_authorised (§11).
    Each result becomes a Finding (source="nuclei"), mapped back to its asset.
    """
    from .models import Tenant, Asset, CVE, Finding

    tenant = Tenant.objects.get(pk=tenant_id)
    if not tenant.scanning_authorised:
        return f"nuclei_scan: ABORTED — no written authorisation for {tenant.slug} (§11)"

    # target -> asset, so we can attribute each hit back to the right asset.
    by_target = {a.target: a for a in tenant.assets.exclude(target="") if a.target}
    targets = list(by_target)
    if not targets:
        return "nuclei_scan: no scannable targets (set the asset 'target' field)"

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name

    # nuclei -update-templates keeps CVE coverage current (§4.1).
    proc = subprocess.run(
        ["nuclei", "-list", targets_file, "-jsonl", "-silent",
         "-severity", "low,medium,high,critical"],
        capture_output=True, text=True, timeout=3600,
    )

    ingested = 0
    for line in proc.stdout.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = r.get("info", {}) or {}
        severity = (info.get("severity") or "info").lower()
        template_id = r.get("template-id", "") or r.get("templateID", "")
        matched_at = r.get("matched-at") or r.get("matched_at") or r.get("host", "")

        # Attribute back to an asset by host/ip.
        host = r.get("host", "") or r.get("ip", "")
        asset = by_target.get(host) or _best_asset(by_target, host)
        if asset is None:
            continue

        # If the template carries a CVE, link/create it; else it's CVE-less.
        cve = None
        cve_ids = (info.get("classification", {}) or {}).get("cve-id") or []
        if cve_ids:
            cve, _ = CVE.objects.get_or_create(
                cve_id=cve_ids[0],
                defaults={"title": info.get("name", ""), "sources": ["nuclei"]},
            )

        Finding.objects.update_or_create(
            asset=asset, source="nuclei", template_id=template_id, matched_at=matched_at,
            defaults={
                "tenant": tenant,
                "cve": cve,
                "title": info.get("name", "")[:400],
                "severity": severity,
                "priority": SEVERITY_TO_PRIORITY.get(severity, "P4"),
                "match_confidence": "scan",
                "match_reason": f"Nuclei: {info.get('name','')} ({template_id})"[:300],
                "last_seen": timezone.now(),
            },
        )
        ingested += 1

    return f"nuclei_scan: {ingested} findings from {len(targets)} target(s) for {tenant.slug}"


def _best_asset(by_target, host):
    """Loose attribution when nuclei's host string differs from the target."""
    for t, a in by_target.items():
        if t and (t in host or host in t):
            return a
    return next(iter(by_target.values()), None)
