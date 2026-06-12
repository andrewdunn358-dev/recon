"""
The dashboard — the "what matters this week and why" view (§4.3), now a proper
login-gated UI. Server-rendered Django templates, lifting the per-tenant
dashboard pattern the brief calls for.
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import Finding

ORDER = ["P1", "P2", "P3", "P4", "P?"]


@login_required
def dashboard(request):
    findings = list(Finding.objects.select_related("cve", "asset", "tenant", "product"))
    findings.sort(key=lambda f: (ORDER.index(f.priority), -(f.cve.epss or 0)))

    ctx = {
        "findings": findings,
        "total": len(findings),
        "kev_count": sum(1 for f in findings if f.cve.in_kev),
        "review_count": sum(1 for f in findings if f.priority == "P?"),
        "exposed_count": sum(1 for f in findings if f.asset.internet_facing),
    }
    return render(request, "recon/dashboard.html", ctx)
