"""
Fire an external Nuclei scan against a tenant's authorised assets and print
what came back. Run this in the scan-worker container (it has the nuclei binary):

    docker compose exec scan-worker python manage.py scan_tenant <slug>

Gated on tenant.scanning_authorised (§11) — aborts without written authorisation.
"""
from django.core.management.base import BaseCommand, CommandError
from core.models import Tenant, Finding
from core.tasks import nuclei_scan


class Command(BaseCommand):
    help = "Run an external Nuclei scan for a tenant and show the findings."

    def add_arguments(self, parser):
        parser.add_argument("slug", help="Tenant slug to scan.")

    def handle(self, *args, **opts):
        try:
            tenant = Tenant.objects.get(slug=opts["slug"])
        except Tenant.DoesNotExist:
            raise CommandError(f"No tenant with slug '{opts['slug']}'.")

        targets = [a.target for a in tenant.assets.exclude(target="") if a.target]
        self.stdout.write(self.style.WARNING(
            f"Scanning {tenant.name}: {len(targets)} target(s) — {', '.join(targets) or 'none'}"))
        if not tenant.scanning_authorised:
            self.stdout.write(self.style.ERROR(
                "Tenant is not authorised for scanning (§11). "
                "Tick 'scanning authorised' in admin once you have written sign-off."))
            return

        self.stdout.write("Running Nuclei (this can take a while)...")
        result = nuclei_scan(tenant.id)
        self.stdout.write(self.style.SUCCESS(result))

        scan_findings = Finding.objects.filter(
            tenant=tenant, source="nuclei").select_related("asset")
        if not scan_findings:
            self.stdout.write("\nNo scan findings. A bare host with few exposed "
                              "services often returns nothing — that's a valid result.")
            return
        self.stdout.write("\nScan findings:")
        for f in scan_findings.order_by("priority"):
            self.stdout.write(
                f"  {f.priority}  [{f.severity:<8}] {f.asset.name}  "
                f"{f.title}  ({f.matched_at})")
