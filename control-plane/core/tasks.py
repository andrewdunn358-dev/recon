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


def upsert_cve(flat: dict):
    """
    Write one CVE record and refresh its product-token index. Shared by the
    incremental feed pull and (a bulk variant of) the full-corpus loader so the
    index never drifts from the affected[] data.
    """
    from .models import CVE, CveProductToken
    from .matching import affected_product_tokens

    cid = flat["cve_id"] if "cve_id" in flat else flat.get("id")
    affected = flat.get("affected", [])
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
            "affected": affected,
            "references": flat.get("references", []),
            "sources": flat.get("sources", []),
            "published": flat.get("published"),
            "last_modified": timezone.now(),
        },
    )
    CveProductToken.objects.filter(cve_id=cid).delete()
    toks = affected_product_tokens(affected)
    if toks:
        CveProductToken.objects.bulk_create(
            [CveProductToken(cve_id=cid, token=t) for t in toks],
            ignore_conflicts=True,
        )


@shared_task
def feed_pull(use_fixtures: bool = False):
    """
    Refresh the CVE store from the multi-source feed mix. In the sandbox call
    with use_fixtures=True; in production leave it False to hit the real feeds.
    """
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
        flat.setdefault("cve_id", cid)
        upsert_cve(flat)
        n += 1
    return f"feed_pull: upserted {n} CVEs ({src})"


@shared_task
def watch_loop():
    """
    The core loop. For every product each tenant runs, look for matching CVEs,
    prioritise, and raise/refresh a Finding. Returns a summary string.

    Candidate CVEs come from the product-token index (CveProductToken), so this
    scales to the full corpus: we only run the fine-grained matcher against CVEs
    whose affected products share a token with the product name, not all 250k.
    """
    from .models import Product, CVE, Finding, CveProductToken
    from .matching import tokens as name_tokens

    raised, refreshed = 0, 0

    for product in Product.objects.select_related("asset", "asset__tenant"):
        asset = product.asset
        ptoks = {t for t in name_tokens(product.name) if len(t) > 1 and not t.isdigit()}
        if not ptoks:
            continue
        cand_ids = (CveProductToken.objects
                    .filter(token__in=ptoks)
                    .values_list("cve_id", flat=True).distinct())
        for cve in CVE.objects.filter(cve_id__in=list(cand_ids)):
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
def nuclei_scan(tenant_id: int, only_targets=None):
    """
    Active external scan with Nuclei against a tenant's authorised assets.
    Phase 0 = external only. Hard-gated on tenant.scanning_authorised (§11).
    Each result becomes a Finding (source="nuclei"), mapped back to its asset.

    only_targets: if given, scan just those targets (used by ad-hoc assess so a
    single-target run doesn't sweep the whole tenant's assets).
    """
    from .models import Tenant, Asset, CVE, Finding

    tenant = Tenant.objects.get(pk=tenant_id)
    if not tenant.scanning_authorised:
        return f"nuclei_scan: ABORTED — no written authorisation for {tenant.slug} (§11)"

    # target -> asset, so we can attribute each hit back to the right asset.
    by_target = {a.target: a for a in tenant.assets.exclude(target="") if a.target}
    if only_targets:
        wanted = set(only_targets)
        by_target = {t: a for t, a in by_target.items() if t in wanted}
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
        if ingest_nuclei_record(tenant, by_target, r):
            ingested += 1

    return f"nuclei_scan: {ingested} findings from {len(targets)} target(s) for {tenant.slug}"


def _best_asset(by_target, host):
    """Loose attribution when nuclei's host string differs from the target."""
    for t, a in by_target.items():
        if t and (t in host or host in t):
            return a
    return next(iter(by_target.values()), None)


def _stream(cmd, input_text=None):
    """
    Run a tool and yield its stdout lines AS THEY ARRIVE (not after it finishes).
    This is what lets the dashboard show discovery/scan results live instead of a
    silent multi-minute wait.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    if input_text is not None:
        try:
            proc.stdin.write(input_text)
        finally:
            proc.stdin.close()
    try:
        for line in proc.stdout:
            line = line.strip()
            if line:
                yield line
    finally:
        proc.stdout.close()
        proc.wait()


def _ingest_httpx_record(tenant, r):
    """Create/refresh the asset + its products from one httpx record. -> (new_asset, new_products)."""
    from .models import Asset, Product
    from . import discovery
    host = r.get("host")
    if not host:
        return 0, 0
    asset, created = Asset.objects.get_or_create(
        tenant=tenant, target=host,
        defaults={"name": host, "kind": Asset.Kind.WEBAPP, "internet_facing": True})
    if not asset.internet_facing:
        asset.internet_facing = True
    if asset.kind == Asset.Kind.HOST:
        asset.kind = Asset.Kind.WEBAPP
    asset.last_seen = timezone.now()
    asset.save()
    np = 0
    techs = list(r.get("tech", []))
    if r.get("webserver"):
        techs.append(r["webserver"])
    for tech in techs:
        info = discovery.split_tech(tech)
        if not info["name"] or not discovery.is_product_tech(info["name"]):
            continue
        _, made = Product.objects.get_or_create(
            asset=asset, name=info["name"], version=info["version"],
            defaults={"vendor": info["vendor"], "source": "httpx"})
        np += int(made)
    return int(created), np


def ingest_nuclei_record(tenant, by_target, r, scan_job=None):
    """Turn one Nuclei JSONL record into a Finding (attributed to scan_job if given)."""
    from .models import CVE, Finding
    info = r.get("info", {}) or {}
    severity = (info.get("severity") or "info").lower()
    template_id = r.get("template-id", "") or r.get("templateID", "")
    matched_at = r.get("matched-at") or r.get("matched_at") or r.get("host", "")
    host = r.get("host", "") or r.get("ip", "")
    asset = by_target.get(host) or _best_asset(by_target, host)
    if asset is None:
        return None
    cve = None
    cve_ids = (info.get("classification", {}) or {}).get("cve-id") or []
    if cve_ids:
        cve, _ = CVE.objects.get_or_create(
            cve_id=cve_ids[0],
            defaults={"title": info.get("name", ""), "sources": ["nuclei"]})
    f, _ = Finding.objects.update_or_create(
        asset=asset, source="nuclei", template_id=template_id, matched_at=matched_at,
        defaults={
            "tenant": tenant, "cve": cve, "title": info.get("name", "")[:400],
            "severity": severity, "priority": SEVERITY_TO_PRIORITY.get(severity, "P4"),
            "match_confidence": "scan",
            "match_reason": f"Nuclei: {info.get('name','')} ({template_id})"[:300],
            "references": (info.get("reference") or [])[:6],
            "remediation": (info.get("remediation") or "")[:1000],
            "last_seen": timezone.now(), "scan_job": scan_job,
        })
    return f


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

    # 1) subdomains (passive). Seed with the roots themselves. IPs can't be
    #    enumerated, so they go straight through to the httpx probe.
    hosts = set(roots)
    for root in roots:
        if discovery.looks_like_ip(root):
            continue
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
    new_assets = new_products = 0
    for r in live:
        a, p = _ingest_httpx_record(tenant, r)
        new_assets += a
        new_products += p

    port_note = f", {sum(len(v) for v in ports.values())} open ports" if do_ports else ""
    return (f"external_discovery: {tenant.slug} — {len(hosts)} hosts enumerated, "
            f"{len(live)} live, +{new_assets} assets, +{new_products} products{port_note}")


@shared_task
def load_cve_corpus(batch_size: int = 2000, limit: int = 0, rebuild_tokens: bool = True):
    """
    Load the ENTIRE local cvelistV5 mirror into the CVE store + token index, so
    matching runs against every CVE on file — not just KEV-plus-recent. One-off
    after the first mirror clone; cheap to re-run (it upserts). KEV/EPSS are
    folded in from their small live feeds.

    Heavy but bounded: ~250k records, processed in batches. Run it in the
    background (worker) rather than blocking a request.
    """
    from pathlib import Path as _Path
    from .models import CVE, CveProductToken
    from .matching import affected_product_tokens

    if not feeds.mirror_present():
        return "load_cve_corpus: no local mirror — run update_cve_mirror first"

    kev = feeds.fetch_kev()
    epss = feeds.fetch_epss()

    if rebuild_tokens:
        CveProductToken.objects.all().delete()

    cve_fields = ["title", "summary", "in_kev", "kev_date_added", "epss", "cvss",
                  "cwe", "affected", "references", "sources", "published", "last_modified"]
    root = _Path(feeds.CVELIST_DIR, "cves")
    total = tok_total = 0
    cve_batch, tok_batch = [], []

    def flush():
        nonlocal cve_batch, tok_batch, total, tok_total
        if cve_batch:
            CVE.objects.bulk_create(
                cve_batch, update_conflicts=True,
                unique_fields=["cve_id"], update_fields=cve_fields)
            total += len(cve_batch)
        if tok_batch:
            CveProductToken.objects.bulk_create(tok_batch, ignore_conflicts=True)
            tok_total += len(tok_batch)
        cve_batch, tok_batch = [], []

    for path in root.glob("*/*/CVE-*.json"):
        try:
            flat = feeds.parse_cve_record(json.loads(path.read_text()))
        except Exception:
            continue
        cid = flat.get("cve_id") or path.stem
        cve_batch.append(CVE(
            cve_id=cid,
            title=flat.get("title", ""), summary=flat.get("summary", ""),
            in_kev=cid in kev, kev_date_added=kev.get(cid),
            epss=epss.get(cid), cvss=flat.get("cvss"), cwe=flat.get("cwe", ""),
            affected=flat.get("affected", []), references=flat.get("references", []),
            sources=flat.get("sources", []),
            published=flat.get("published"), last_modified=timezone.now(),
        ))
        for t in affected_product_tokens(flat.get("affected", [])):
            tok_batch.append(CveProductToken(cve_id=cid, token=t))

        if len(cve_batch) >= batch_size:
            flush()
        if limit and total >= limit:
            break

    flush()
    return f"load_cve_corpus: {total} CVEs loaded, {tok_total} product tokens indexed"


@shared_task
def adhoc_assess(job_id: int):
    """
    Dashboard-triggered assessment that reports progress AS IT GOES. Runs on the
    scan-worker. Persists discovery results immediately (so they show within a
    minute or two), then streams Nuclei findings one at a time — each phase and
    each finding updates the ScanJob the page is polling. Findings are tagged
    with the job so the panel can stream this run's results live.
    """
    from .models import ScanJob, Tenant, Asset
    from .matching import tokens as name_tokens, match_product_to_cve
    from .models import Product, CVE, Finding, CveProductToken
    from . import discovery

    job = ScanJob.objects.get(pk=job_id)

    def upd(**kw):
        for k, v in kw.items():
            setattr(job, k, v)
        job.save(update_fields=list(kw))

    upd(status=ScanJob.Status.RUNNING, started_at=timezone.now(), phase="starting…")
    try:
        target = job.target.strip()
        tenant = job.tenant
        if tenant is None:
            tenant, _ = Tenant.objects.get_or_create(
                slug="ad-hoc",
                defaults={"name": "Ad-hoc / Unassigned", "scanning_authorised": True})
            job.tenant = tenant
            job.save(update_fields=["tenant"])

        base = target.split("/")[0]
        is_ip = discovery.looks_like_ip(target)
        Asset.objects.get_or_create(
            tenant=tenant, target=target,
            defaults={"name": target, "kind": Asset.Kind.IP if is_ip else Asset.Kind.DOMAIN,
                      "internet_facing": True})

        # Phase 1 — subdomains (skip for IPs).
        hosts = {target}
        if not is_ip:
            upd(phase=f"Enumerating subdomains of {target}…")
            for line in _stream(["subfinder", "-silent", "-d", target]):
                hosts |= set(discovery.parse_subfinder(line))
        upd(phase=f"Found {len(hosts)} host(s) — probing which are live…",
            total=len(hosts), progress=0)

        # Phase 2 — httpx, streamed: assets/products appear as each host responds.
        n_assets = n_products = probed = 0
        for line in _stream(["httpx", "-silent", "-json", "-tech-detect", "-title", "-web-server"],
                            input_text="\n".join(sorted(hosts))):
            for r in discovery.parse_httpx(line):
                a, p = _ingest_httpx_record(tenant, r)
                n_assets += a
                n_products += p
                probed += 1
                upd(phase=f"Live: {probed} web host(s), {n_products} product(s) found…",
                    progress=probed)

        # Phase 3 — match discovered products against the full CVE corpus.
        upd(phase=f"{probed} live host(s), {n_products} product(s). Matching against CVE corpus…")
        cve_matches = 0
        prods = Product.objects.filter(
            asset__tenant=tenant, asset__target__icontains=base).select_related("asset")
        for product in prods:
            ptoks = {t for t in name_tokens(product.name) if len(t) > 1 and not t.isdigit()}
            if not ptoks:
                continue
            cand = (CveProductToken.objects.filter(token__in=ptoks)
                    .values_list("cve_id", flat=True).distinct())
            for cve in CVE.objects.filter(cve_id__in=list(cand)):
                m = match_product_to_cve(product, cve)
                if not m:
                    continue
                Finding.objects.update_or_create(
                    asset=product.asset, cve=cve, product=product,
                    defaults={"tenant": tenant,
                              "priority": prioritise(cve, product.asset, m.confidence),
                              "match_confidence": m.confidence, "match_reason": m.reason,
                              "last_seen": timezone.now(), "scan_job": job})
                cve_matches += 1
                upd(phase=f"Matched {cve_matches} CVE(s) so far…")

        # Phase 4 — Nuclei deep scan (optional), streamed finding-by-finding.
        nuclei_found = 0
        if job.do_nuclei:
            by_target = {a.target: a for a in
                         tenant.assets.exclude(target="").filter(target__icontains=base) if a.target}
            tlist = list(by_target) or [target]
            upd(phase=f"Deep scanning {len(tlist)} host(s) with Nuclei — the slow part…",
                total=len(tlist), progress=0)
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(tlist))
                tfile = tf.name
            for line in _stream(["nuclei", "-list", tfile, "-jsonl", "-silent",
                                 "-severity", "low,medium,high,critical"]):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ingest_nuclei_record(tenant, by_target, r, scan_job=job):
                    nuclei_found += 1
                    upd(phase=f"Nuclei: {nuclei_found} finding(s) so far…", progress=nuclei_found)

        job.summary = (f"{probed} live host(s), {n_products} product(s); "
                       f"{cve_matches} CVE match(es), {nuclei_found} scan finding(s).")
        upd(status=ScanJob.Status.DONE, phase="done", finished_at=timezone.now())
        job.save(update_fields=["summary"])
    except Exception as e:  # noqa: BLE001 — surface to the user
        job.summary = f"error: {e}"
        upd(status=ScanJob.Status.FAILED, phase="failed", finished_at=timezone.now())
        job.save(update_fields=["summary"])
    return f"adhoc_assess[{job_id}]: {job.status}"


@shared_task
def sync_synthops():
    """
    Read Recon's inventory from SynthOps (the source of truth) and retire the
    direct TRMM pull: clients -> tenants, servers/workstations -> assets, and
    each device's TRMM software list -> products. The matcher then runs over it.
    SynthOps already aggregates TRMM, so this is one read instead of two systems.
    """
    from django.utils.text import slugify
    from .models import Tenant, Asset, Product
    from .integrations.synthops import SynthOps
    from .integrations import trmm

    so = SynthOps()
    so.login()

    # clients -> tenants (keep a map so devices attach to the right one).
    by_client = {}
    new_tenants = 0
    for c in so.clients():
        name = (c.get("name") or "Unknown").strip()
        slug = slugify(c.get("code") or name)[:50] or "client"
        tenant, created = Tenant.objects.get_or_create(slug=slug, defaults={"name": name})
        if tenant.name != name:
            tenant.name = name
            tenant.save(update_fields=["name"])
        by_client[c.get("id")] = tenant
        new_tenants += int(created)

    # servers + workstations -> assets. Tag the source so we can report counts,
    # and isolate each device so one failure can't abort the whole sync.
    try:
        server_list = so.servers()
    except Exception as e:
        server_list = []
        print(f"sync_synthops: /servers fetch failed: {e}")
    try:
        ws_list = so.workstations()
    except Exception as e:
        ws_list = []
        print(f"sync_synthops: /workstations fetch failed: {e}")

    n_servers = n_ws = n_products = errors = 0
    # Phase A: create/update assets (sequential DB), collecting agents to query.
    agent_jobs = []  # (asset, agent_id)
    for kind_label, d in ([("server", s) for s in server_list]
                          + [("workstation", w) for w in ws_list]):
        try:
            tenant = by_client.get(d.get("client_id"))
            if tenant is None:
                cname = (d.get("client_name") or "Unknown").strip()
                tenant, _ = Tenant.objects.get_or_create(
                    slug=slugify(cname)[:50] or "unknown", defaults={"name": cname})

            host = d.get("hostname") or str(d.get("id"))
            public_ip = (d.get("public_ip") or "").strip()
            target = public_ip or (d.get("ip_address") or "").strip() or host
            asset, _ = Asset.objects.update_or_create(
                tenant=tenant, name=host,
                defaults={"kind": Asset.Kind.HOST, "target": target,
                          "internet_facing": bool(public_ip), "last_seen": timezone.now()})
            if kind_label == "server":
                n_servers += 1
            else:
                n_ws += 1
            agent_id = d.get("tactical_rmm_agent_id")
            if agent_id:
                agent_jobs.append((asset, agent_id))
        except Exception as e:  # one bad device must not lose the rest
            errors += 1
            print(f"sync_synthops: skipped {d.get('hostname')}: {e}")

    print(f"sync_synthops: {n_servers} servers + {n_ws} workstations as assets; "
          f"fetching software for {len(agent_jobs)} agents (parallel)...")

    # Phase B: fetch software concurrently — network only, no ORM in threads.
    from concurrent.futures import ThreadPoolExecutor
    software = {}
    done = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(so.agent_software, aid): aid for _, aid in agent_jobs}
        for fut in futures:
            aid = futures[fut]
            try:
                software[aid] = fut.result()
            except Exception:
                software[aid] = []
            done += 1
            if done % 20 == 0:
                print(f"sync_synthops: software {done}/{len(agent_jobs)}...")

    # Phase C: write products (sequential DB) from the fetched results.
    for asset, agent_id in agent_jobs:
        asset.products.filter(source="synthops").delete()
        for sw in software.get(agent_id, []):
            row = trmm.normalise_software(sw)
            if not row["name"]:
                continue
            Product.objects.create(asset=asset, source="synthops", **row)
            n_products += 1

    watch_loop()
    return (f"sync_synthops: {len(by_client)} clients ({new_tenants} new), "
            f"{n_servers} servers, {n_ws} workstations, {n_products} products, "
            f"{errors} skipped")
