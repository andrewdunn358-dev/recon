"""
The dashboard — the "what matters this week and why" view (§4.3), now a proper
login-gated UI. Server-rendered Django templates, lifting the per-tenant
dashboard pattern the brief calls for. Handles both watch findings (CVE-backed)
and active-scan findings (Nuclei, often CVE-less).
"""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from .models import Finding, ScanJob
from .tasks import adhoc_assess

ORDER = ["P1", "P2", "P3", "P4", "P?"]


def _epss(f):
    return (f.cve.epss or 0) if f.cve else 0


def _truthy(v):
    return str(v).lower() in ("on", "true", "1", "yes")


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

    job = ScanJob.objects.create(
        target=target,
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
    return JsonResponse({
        "status": job.status,
        "summary": job.summary,
        "target": job.target,
    })
