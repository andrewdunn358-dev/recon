"""
Run the full Phase 0 loop synchronously and print a readable report:
  feed_pull (fixtures) -> watch_loop (match + prioritise) -> findings table.

This is the "new CVE -> matched to a product I run -> alert" proof end to end.
"""
from django.core.management.base import BaseCommand
from core.tasks import feed_pull, watch_loop
from core.models import Finding, CVE, Product

ORDER = ["P1", "P2", "P3", "P4", "P?"]


class Command(BaseCommand):
    help = "Run the watch loop against the fixture feeds and print findings."

    def add_arguments(self, parser):
        parser.add_argument(
            "--live", action="store_true",
            help="Pull real feeds (KEV/EPSS/cvelistV5) instead of fixtures.",
        )

    def handle(self, *args, **opts):
        live = opts["live"]
        src = "live feeds" if live else "fixtures"
        self.stdout.write(self.style.WARNING(f"1. Pulling feeds ({src})..."))
        self.stdout.write("   " + feed_pull(use_fixtures=not live))
        self.stdout.write(f"   CVEs in store: {CVE.objects.count()} "
                          f"({CVE.objects.filter(in_kev=True).count()} in KEV)")
        self.stdout.write(f"   Products to check: {Product.objects.count()}")

        self.stdout.write(self.style.WARNING("\n2. Running watch loop (match + prioritise)..."))
        self.stdout.write("   " + watch_loop())

        self.stdout.write(self.style.WARNING("\n3. Findings (prioritised):\n"))
        rows = sorted(
            Finding.objects.select_related("cve", "asset", "product"),
            key=lambda f: (ORDER.index(f.priority), -((f.cve.epss or 0) if f.cve else 0)),
        )
        hdr = f"   {'PRI':<4}{'CVE':<18}{'KEV':<5}{'EPSS':<6}{'ASSET':<16}{'CONF':<8}REASON"
        self.stdout.write(self.style.HTTP_INFO(hdr))
        self.stdout.write("   " + "-" * 92)
        for f in rows:
            kev = "yes" if (f.cve and f.cve.in_kev) else "-"
            epss = f"{f.cve.epss:.2f}" if (f.cve and f.cve.epss is not None) else "-"
            label = f.cve_id or f.label
            line = (f"   {f.priority:<4}{label:<18}{kev:<5}{epss:<6}"
                    f"{f.asset.name:<16}{f.match_confidence:<8}{f.match_reason}")
            style = self.style.ERROR if f.priority == "P1" else (
                self.style.WARNING if f.priority in ("P2", "P?") else lambda x: x)
            self.stdout.write(style(line) if callable(style) else line)

        self.stdout.write(self.style.SUCCESS(
            f"\n   {len(rows)} findings raised. "
            f"P1={sum(1 for f in rows if f.priority=='P1')} "
            f"review={sum(1 for f in rows if f.priority=='P?')}"))
