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
from pathlib import Path
from celery import shared_task
from django.utils import timezone

from . import feeds
from .matching import match_product_to_cve
from .prioritise import prioritise


@shared_task
def update_cve_mirror():
    """
    Clone or update the local cvelistV5 mirror (§5.2). First run shallow-clones
    it (a few GB onto the persistent volume); later runs `git pull` only the
    daily deltas. feed_pull then reads records from this local copy rather than
    hitting GitHub per-record — fast, and no rate limits.
    """
    target = feeds.CVELIST_DIR
    if Path(target, ".git").is_dir():
        cmd = ["git", "-C", target, "pull", "--no-edit"]
        action = "pull"
    else:
        Path(target).mkdir(parents=True, exist_ok=True)
        cmd = ["git", "clone", "--depth", "1", feeds.CVELIST_REPO, target]
        action = "clone"
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    if proc.returncode == 0:
        return f"update_cve_mirror: {action} ok ({target})"
    return f"update_cve_mirror: {action} FAILED — {proc.stderr.strip()[-300:]}"


@shared_task
def feed_pull(use_fixtures: bool = False):
    """
    Refresh the CVE store from the multi-source feed mix. In the sandbox call
    with use_fixtures=True; in production leave it False to hit the real feeds.
    """
    from .models import CVE

    if use_fixtures:
        bundle = feeds.load_fixtures()
        src = "fixtures"
    elif feeds.mirror_present():
        # Preferred: read CVE records off the local cvelistV5 mirror (fast, no
        # rate limits). KEV/EPSS are still small live downloads.
        bundle = feeds.assemble_local()
        src = "local mirror"
    else:
        # Fallback until the mirror is cloned: per-record fetch from GitHub.
        bundle = feeds.assemble_live()
        src = "live (no mirror yet)"
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
    return f"feed_pull: upserted {n} CVEs ({src})"


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
        print(f"[ALERT] {f.tenant.name}: {f.label} on {f.asset.name} "
              f"-> {f.get_priority_display()} ({f.match_confidence}: {f.match_reason})")
    count = pending.update(notified=True)
    return f"notify: {count} findings notified"


@shared_task
def sync_trmm():
    """
    Pull installed-software inventory from Tactical RMM and load it as the
    internal feeder (§4.1): clients -> tenants, agents -> assets, software ->
    products. The same Product x CVE matcher then runs over it — no new agent,
    Recon just reads the one you already deploy.
    """
    from django.utils.text import slugify
    from django.utils import timezone as tz
    from .models import Tenant, Asset, Product
    from .integrations import trmm

    agents = trmm.list_agents()
    n_assets = n_products = 0

    for ag in agents:
        client = (ag.get("client_name") or "Unknown").strip()
        tenant, _ = Tenant.objects.get_or_create(
            slug=slugify(client)[:50] or "unknown",
            defaults={"name": client},
        )
        host = ag.get("hostname") or ag.get("agent_id")
        asset, _ = Asset.objects.update_or_create(
            tenant=tenant, name=host,
            defaults={"kind": Asset.Kind.HOST, "internet_facing": False,
                      "last_seen": tz.now()},
        )
        n_assets += 1

        # Refresh this asset's TRMM-sourced products (leave scan/manual ones).
        asset.products.filter(source="trmm").delete()
        for sw in trmm.get_software(ag["agent_id"]):
            row = trmm.normalise_software(sw)
            if not row["name"]:
                continue
            Product.objects.create(asset=asset, source="trmm", **row)
            n_products += 1

    return f"sync_trmm: {len(agents)} agents -> {n_assets} assets, {n_products} products"


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


@shared_task
def external_discovery(tenant_id: int, roots=None, do_ports: bool = False):
    """
    Step 1 — agentless external discovery. Enumerate subdomains of the tenant's
    root domains, probe which are live, fingerprint the tech stack, and ingest
    the result as Assets + Products so the Product×CVE matcher can act on them.

    Chain: subfinder -> httpx (-> naabu if do_ports). Hard-gated on
    scanning_authorised (§11). Runs in the scan-worker image (it has the tools).
    """
    from .models import Tenant, Asset, Product
    from . import discovery

    tenant = Tenant.objects.get(pk=tenant_id)
    if not tenant.scanning_authorised:
        return f"external_discovery: ABORTED — no written authorisation for {tenant.slug} (§11)"

    if not roots:
        roots = [a.target for a in tenant.assets.filter(kind=Asset.Kind.DOMAIN) if a.target]
    roots = sorted({r.strip() for r in (roots or []) if r and r.strip()})
    if not roots:
        return (f"external_discovery: no root domains for {tenant.slug} — add a "
                f"domain asset or pass roots=[...]")

    # 1) subdomains (passive). Seed with the roots themselves.
    hosts = set(roots)
    for root in roots:
        try:
            p = subprocess.run(["subfinder", "-silent", "-d", root],
                               capture_output=True, text=True, timeout=600)
            hosts |= set(discovery.parse_subfinder(p.stdout))
        except FileNotFoundError:
            return "external_discovery: subfinder not found — run this in the scan-worker container"
        except subprocess.TimeoutExpired:
            pass

    # 2) probe live web + fingerprint
    probe = subprocess.run(
        ["httpx", "-silent", "-json", "-tech-detect", "-title", "-web-server"],
        input="\n".join(sorted(hosts)), capture_output=True, text=True, timeout=1200)
    live = discovery.parse_httpx(probe.stdout)

    # 3) optional port sweep
    ports = {}
    if do_ports:
        sweep = subprocess.run(["naabu", "-silent", "-json", "-list", "-"],
                               input="\n".join(sorted(hosts)),
                               capture_output=True, text=True, timeout=1200)
        ports = discovery.parse_naabu(sweep.stdout)

    # ---- ingest ----------------------------------------------------------
    now = timezone.now()
    new_assets = new_products = 0
    for r in live:
        host = r["host"]
        if not host:
            continue
        asset, created = Asset.objects.get_or_create(
            tenant=tenant, target=host,
            defaults={"name": host, "kind": Asset.Kind.WEBAPP, "internet_facing": True},
        )
        changed = False
        if not asset.internet_facing:
            asset.internet_facing = True; changed = True
        if asset.kind == Asset.Kind.HOST:
            asset.kind = Asset.Kind.WEBAPP; changed = True
        asset.last_seen = now
        asset.save()
        new_assets += int(created)

        techs = list(r["tech"])
        if r["webserver"]:
            techs.append(r["webserver"])
        for tech in techs:
            info = discovery.split_tech(tech)
            if not info["name"]:
                continue
            _, made = Product.objects.get_or_create(
                asset=asset, name=info["name"], version=info["version"],
                defaults={"vendor": info["vendor"], "source": "httpx"},
            )
            new_products += int(made)

    port_note = f", {sum(len(v) for v in ports.values())} open ports" if do_ports else ""
    return (f"external_discovery: {tenant.slug} — {len(hosts)} hosts enumerated, "
            f"{len(live)} live, +{new_assets} assets, +{new_products} products{port_note}")
