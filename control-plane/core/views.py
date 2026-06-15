"""
The dashboard — the "what matters this week and why" view (§4.3), now a proper
login-gated UI. Server-rendered Django templates, lifting the per-tenant
dashboard pattern the brief calls for. Handles both watch findings (CVE-backed)
and active-scan findings (Nuclei, often CVE-less).
"""
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
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


@login_required
def dashboard(request):
    findings = list(Finding.objects.select_related("cve", "asset", "tenant", "product"))
    findings.sort(key=lambda f: (ORDER.index(f.priority), -_epss(f)))

    ctx = {
        "findings": findings,
        "total": len(findings),
        "kev_count": sum(1 for f in findings if f.cve and f.cve.in_kev),
        "review_count": sum(1 for f in findings if f.priority == "P?"),
        "exposed_count": sum(1 for f in findings if f.asset.internet_facing),
        "scan_count": sum(1 for f in findings if f.source == "nuclei"),
        "recent_jobs": ScanJob.objects.all()[:8],
    }
    return render(request, "recon/dashboard.html", ctx)


@login_required
def clients(request):
    tenants = Tenant.objects.annotate(
        asset_count=Count("assets", distinct=True),
        exposed_count=Count("assets", filter=Q(assets__internet_facing=True), distinct=True),
        finding_count=Count("findings", distinct=True),
        p1_count=Count("findings", filter=Q(findings__priority="P1"), distinct=True),
    ).order_by("-p1_count", "name")
    return render(request, "recon/clients.html", {"tenants": tenants})


@login_required
def client_detail(request, slug):
    tenant = get_object_or_404(Tenant, slug=slug)
    assets = (tenant.assets.prefetch_related("products", "findings")
              .order_by("-internet_facing", "name"))
    findings = _sort_findings(
        tenant.findings.select_related("cve", "asset", "product"))
    offline = [a for a in assets if a.status and a.status != "online"]
    ctx = {
        "tenant": tenant,
        "assets": assets,
        "findings": findings,
        "kev_count": sum(1 for f in findings if f.cve and f.cve.in_kev),
        "review_count": sum(1 for f in findings if f.priority == "P?"),
        "online_count": sum(1 for a in assets if a.status == "online"),
        "offline_count": len(offline),
        "last_job": tenant.scan_jobs.order_by("-created_at").first(),
        "remediation_enabled": trmm.remediation_enabled(),
    }
    return render(request, "recon/client_detail.html", ctx)


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
