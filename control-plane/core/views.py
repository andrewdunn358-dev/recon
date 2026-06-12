"""
A single plain findings board — the "three things that matter this week" view
(§4.3), read-only. Deliberately unstyled for Phase 0; the designed per-tenant
dashboard lands in Phase 1.
"""
from django.http import HttpResponse
from .models import Finding

ORDER = ["P1", "P2", "P3", "P4", "P?"]


def findings_board(request):
    rows = list(Finding.objects.select_related("cve", "asset", "tenant"))
    rows.sort(key=lambda f: (ORDER.index(f.priority), -(f.cve.epss or 0)))

    html = ["<h1>Recon — findings</h1>",
            "<p>Advisory only. Nothing here runs against a device without "
            "explicit human sign-off (§4.3, §11).</p>",
            "<table border=1 cellpadding=6><tr>"
            "<th>Priority</th><th>CVE</th><th>KEV</th><th>EPSS</th>"
            "<th>Asset</th><th>Tenant</th><th>Match</th><th>Status</th></tr>"]
    for f in rows:
        html.append(
            f"<tr><td>{f.get_priority_display()}</td><td>{f.cve_id}</td>"
            f"<td>{'yes' if f.cve.in_kev else ''}</td>"
            f"<td>{f.cve.epss if f.cve.epss is not None else ''}</td>"
            f"<td>{f.asset.name}</td><td>{f.tenant.name}</td>"
            f"<td>{f.match_confidence}: {f.match_reason}</td>"
            f"<td>{f.get_status_display()}</td></tr>"
        )
    html.append("</table>")
    return HttpResponse("\n".join(html))
