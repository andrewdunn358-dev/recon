"""
The dashboard — the "what matters this week and why" view (§4.3), now a proper
login-gated UI. Server-rendered Django templates, lifting the per-tenant
dashboard pattern the brief calls for. Handles both watch findings (CVE-backed)
and active-scan findings (Nuclei, often CVE-less).
"""
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q, F
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from .models import Finding, ScanJob, Tenant, Asset, RemediationAction
from .tasks import adhoc_assess, assess_client, assess_asset, remediate_via_trmm
from .integrations import trmm

ORDER = ["P1", "P2", "P3", "P4", "P?"]


def _epss(f):
    return (f.cve.epss or 0) if f.cve else 0


def _truthy(v):
    return str(v).lower() in ("on", "true", "1", "yes")


def _sort_findings(qs):
    return sorted(qs, key=lambda f: (ORDER.index(f.priority), -_epss(f)))


def _rank():
    from django.db.models import Case, When, IntegerField
    return Case(When(priority="P1", then=0), When(priority="P2", then=1),
                When(priority="P3", then=2), When(priority="P4", then=3),
                default=4, output_field=IntegerField())


@login_required
def dashboard(request):
    base = Finding.objects.all()
    by_pri = {r["priority"]: r["n"] for r in base.values("priority").annotate(n=Count("id"))}
    top = list(Finding.objects.select_related("cve", "asset", "tenant", "product")
               .annotate(rank=_rank())
               .order_by("rank", F("cve__epss").desc(nulls_last=True))[:40])
    ctx = {
        "findings": top,
        "total": base.count(),
        "kev_count": base.filter(cve__in_kev=True).count(),
        "p1_count": by_pri.get("P1", 0),
        "p2_count": by_pri.get("P2", 0),
        "review_count": by_pri.get("P?", 0),
        "exposed_count": base.filter(asset__internet_facing=True).count(),
        "scan_count": base.filter(source="nuclei").count(),
        "recent_jobs": ScanJob.objects.all()[:8],
    }
    return render(request, "recon/dashboard.html", ctx)


@login_required
def findings(request):
    """Findings grouped by CVE — the unit of work. One row per vulnerability with
    the count of affected devices, expandable to the device list (same-device
    duplicates from multiple inventory entries collapsed)."""
    from django.core.paginator import Paginator
    from django.db.models import Min
    from collections import defaultdict
    sev = request.GET.get("sev") or ""
    client = request.GET.get("client") or ""
    base = Finding.objects.all()
    tenant = None
    if client:
        tenant = Tenant.objects.filter(slug=client).first()
        if tenant:
            base = base.filter(tenant=tenant)
    fqs = base
    if sev in ("P1", "P2", "P3", "P4", "P?"):
        fqs = fqs.filter(priority=sev)

    # Group by CVE. priority codes sort P1<P2<P3<P4<P? lexically, so Min() gives
    # the most severe priority that CVE reached on any device.
    groups = (fqs.values("cve_id", "cve__title", "cve__summary",
                         "cve__in_kev", "cve__epss", "cve__cvss")
                 .annotate(devices=Count("asset", distinct=True),
                           pri=Min("priority"))
                 .order_by("pri", F("cve__epss").desc(nulls_last=True)))
    page = Paginator(groups, 50).get_page(request.GET.get("page"))

    # Affected devices for the CVEs on this page (one query), deduped per asset.
    cve_ids = [g["cve_id"] for g in page]
    by_cve = defaultdict(list)
    if cve_ids:
        seen = set()
        for f in (fqs.filter(cve_id__in=cve_ids)
                  .select_related("asset", "tenant", "product")
                  .annotate(rank=_rank()).order_by("rank", "asset__name")):
            k = (f.cve_id, f.asset_id)
            if k in seen:
                continue
            seen.add(k)
            by_cve[f.cve_id].append(f)

    WORD = {"P1": "Critical", "P2": "High", "P3": "Medium", "P4": "Low", "P?": "Review"}
    rows = []
    for g in page:
        rows.append({
            "cve_id": g["cve_id"], "title": g["cve__title"], "summary": g["cve__summary"],
            "in_kev": g["cve__in_kev"], "epss": g["cve__epss"], "cvss": g["cve__cvss"],
            "devices": g["devices"], "pri": g["pri"],
            "severity_word": WORD.get(g["pri"], "—"),
            "affected": by_cve.get(g["cve_id"], []),
            "nvd": f"https://nvd.nist.gov/vuln/detail/{g['cve_id']}",
        })

    # Chips count DISTINCT CVEs per severity, to match the grouped list.
    counts = {r["priority"]: r["c"] for r in
              base.values("priority").annotate(c=Count("cve", distinct=True))}
    sev_rows = [(code, word, counts.get(code, 0)) for code, word in
                (("P1", "Critical"), ("P2", "High"), ("P3", "Medium"),
                 ("P4", "Low"), ("P?", "Review"))]
    ctx = {
        "page_obj": page, "rows": rows, "sev": sev, "client": client, "tenant": tenant,
        "remediation_enabled": trmm.remediation_enabled(),
        "total_cves": base.values("cve").distinct().count(),
        "total_findings": base.count(),
        "sev_rows": sev_rows,
    }
    return render(request, "recon/findings.html", ctx)


@login_required
def clients(request):
    tenants = Tenant.objects.annotate(
        asset_count=Count("assets", distinct=True),
        exposed_count=Count("assets", filter=Q(assets__internet_facing=True), distinct=True),
        finding_count=Count("findings__cve", distinct=True),
        p1_count=Count("findings__cve", filter=Q(findings__priority="P1"), distinct=True),
    ).order_by("-p1_count", "name")
    return render(request, "recon/clients.html", {"tenants": tenants})


@login_required
def client_detail(request, slug):
    tenant = get_object_or_404(Tenant, slug=slug)
    assets = (tenant.assets.prefetch_related("products", "findings")
              .order_by("-internet_facing", "name"))
    offline = [a for a in assets if a.status and a.status != "online"]
    fcounts = {r["priority"]: r["n"] for r in
               tenant.findings.values("priority").annotate(n=Count("cve", distinct=True))}
    ctx = {
        "tenant": tenant,
        "assets": assets,
        "finding_total": sum(fcounts.values()),
        "sev_counts": [("P1", "Critical", fcounts.get("P1", 0)),
                       ("P2", "High", fcounts.get("P2", 0)),
                       ("P3", "Medium", fcounts.get("P3", 0)),
                       ("P4", "Low", fcounts.get("P4", 0)),
                       ("P?", "Review", fcounts.get("P?", 0))],
        "kev_count": tenant.findings.filter(cve__in_kev=True).count(),
        "online_count": sum(1 for a in assets if a.status == "online"),
        "offline_count": len(offline),
        "last_job": tenant.scan_jobs.order_by("-created_at").first(),
        "remediation_enabled": trmm.remediation_enabled(),
    }
    return render(request, "recon/client_detail.html", ctx)


@login_required
def asset_audit(request, slug, asset_id):
    """Lay the matcher's reasoning bare for one device, so a human who knows the
    machine can verify each finding against ground truth: the installed name and
    version next to the CVE's raw affected data, the exact distinctive token that
    triggered the match, and an in/out/inconclusive verdict per version range."""
    from .matching import candidate_tokens, version_in_range, _describe_range
    tenant = get_object_or_404(Tenant, slug=slug)
    asset = get_object_or_404(Asset, pk=asset_id, tenant=tenant)
    fs = (asset.findings.select_related("cve", "product")
          .annotate(rank=_rank())
          .order_by("rank", F("cve__epss").desc(nulls_last=True)))

    verdict = {
        True:  ("in",      "installed version IS inside this affected range"),
        False: ("out",     "installed version is OUTSIDE this range — patched"),
        None:  ("unknown", "version couldn't be evaluated against this range"),
    }
    audits = []
    for f in fs:
        p, cve = f.product, f.cve
        evidence, why = [], []
        if cve:
            if cve.in_kev:
                why.append("On CISA KEV — known to be exploited in the wild")
            if cve.epss is not None:
                why.append(f"EPSS {cve.epss:.0%} — modelled exploitation probability")
            if cve.cvss is not None:
                why.append(f"CVSS {cve.cvss} base score")
        if asset.internet_facing:
            why.append("This device is internet-facing")
        if cve and p:
            ptoks = candidate_tokens(p.name)
            for aff in (cve.affected or []):
                aprod = aff.get("product", "")
                shared = sorted(ptoks & candidate_tokens(aprod))
                if not shared:
                    continue  # not an entry that could have triggered this match
                ranges = []
                for vr in (aff.get("versions") or []):
                    state, text = verdict[version_in_range(p.version, vr)]
                    ranges.append({"desc": _describe_range(vr), "state": state, "text": text})
                evidence.append({
                    "vendor": aff.get("vendor", ""), "product": aprod,
                    "shared": shared, "ranges": ranges,
                    "no_versions": not aff.get("versions"),
                })
        audits.append({
            "f": f, "product": p, "cve": cve, "evidence": evidence, "why": why,
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}" if cve else "",
        })

    return render(request, "recon/asset_audit.html", {
        "tenant": tenant, "asset": asset, "audits": audits, "total": len(audits),
    })


@login_required
def client_scan_start(request, slug):
    """Queue a whole-client assessment (CVE match all devices; active scan the
    internet-facing online ones if the client is §11-authorised)."""
    tenant = get_object_or_404(Tenant, slug=slug)
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    job = ScanJob.objects.create(
        target=f"client: {tenant.name}",
        tenant=tenant,
        do_nuclei=True,
        created_by=request.user if request.user.is_authenticated else None,
    )
    assess_client.apply_async(args=[job.id], queue="scan")
    return JsonResponse({"job_id": job.id, "status": job.status,
                         "authorised": tenant.scanning_authorised})


@login_required
def asset_scan_start(request, slug, asset_id):
    """Assess one device: inventory CVE match (internal) or +active scan (internet-facing)."""
    tenant = get_object_or_404(Tenant, slug=slug)
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    asset = get_object_or_404(Asset, pk=asset_id, tenant=tenant)
    job = ScanJob.objects.create(
        target=asset.name, tenant=tenant, do_nuclei=asset.internet_facing,
        created_by=request.user if request.user.is_authenticated else None,
    )
    assess_asset.apply_async(args=[job.id, asset.id], queue="scan")
    return JsonResponse({"job_id": job.id, "status": job.status})


@login_required
def remediate_start(request, finding_id):
    """Human-approved push of a software update to a device's TRMM agent. Gated:
    global REMEDIATION_ENABLED, a real agent id, and a software-backed finding."""
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    finding = get_object_or_404(Finding, pk=finding_id)
    asset = finding.asset
    if not trmm.remediation_enabled():
        return JsonResponse({"error": "Remediation is disabled (REMEDIATION_ENABLED off)."}, status=403)
    if not asset.tactical_rmm_agent_id:
        return JsonResponse({"error": "No TRMM agent on this device."}, status=400)
    if not finding.product:
        return JsonResponse({"error": "Only software-update findings can be remediated here."}, status=400)

    action = RemediationAction.objects.create(
        finding=finding, asset=asset, agent_id=asset.tactical_rmm_agent_id,
        kind="software_update", target_ref=finding.product.name,
        requested_by=request.user if request.user.is_authenticated else None,
    )
    remediate_via_trmm.apply_async(args=[action.id], queue="scan")
    return JsonResponse({"action_id": action.id, "status": action.status})


@login_required
def remediate_status(request):
    try:
        act = RemediationAction.objects.get(pk=request.GET.get("action"))
    except (RemediationAction.DoesNotExist, ValueError, TypeError):
        return JsonResponse({"error": "unknown action"}, status=404)
    return JsonResponse({"status": act.status, "output": act.output[:600]})


@login_required
def scan_start(request):
    """Queue an ad-hoc assessment to the scan worker. §11 consent is required."""
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    target = (request.POST.get("target") or "").strip()
    if not target:
        return JsonResponse({"error": "Enter a domain or IP."}, status=400)
    if not _truthy(request.POST.get("authorised")):
        return JsonResponse(
            {"error": "Confirm you are authorised to scan this target (§11)."}, status=400)

    job_tenant = None
    slug = request.POST.get("tenant")
    if slug:
        job_tenant = Tenant.objects.filter(slug=slug).first()

    job = ScanJob.objects.create(
        target=target,
        tenant=job_tenant,
        do_ports=_truthy(request.POST.get("ports")),
        do_nuclei=_truthy(request.POST.get("nuclei")),
        created_by=request.user if request.user.is_authenticated else None,
    )
    adhoc_assess.apply_async(args=[job.id], queue="scan")
    return JsonResponse({"job_id": job.id, "status": job.status})


@login_required
def scan_status(request):
    try:
        job = ScanJob.objects.get(pk=request.GET.get("job"))
    except (ScanJob.DoesNotExist, ValueError, TypeError):
        return JsonResponse({"error": "unknown job"}, status=404)

    findings = [{
        "priority": f.priority,
        "label": f.label,
        "asset": f.asset.name,
        "kev": bool(f.cve and f.cve.in_kev),
        "reason": f.match_reason or f.title,
    } for f in job.findings.select_related("asset", "cve").order_by("priority")[:200]]

    return JsonResponse({
        "status": job.status,
        "phase": job.phase,
        "progress": job.progress,
        "total": job.total,
        "summary": job.summary,
        "target": job.target,
        "findings": findings,
        "count": len(findings),
    })
