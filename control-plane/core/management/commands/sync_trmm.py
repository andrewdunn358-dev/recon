"""
Pull installed-software inventory from Tactical RMM and match it against the
CVE feeds — the internal/managed-device half of the picture.

    docker compose exec web python manage.py sync_trmm

Needs TRMM_API_URL + TRMM_API_KEY in .env. Make sure the CVE store is populated
first (run_watch_loop --live, or wait for the nightly pull).
"""
from django.core.management.base import BaseCommand
from core.tasks import sync_trmm, watch_loop
from core.integrations.trmm import TRMMError
from core.models import Finding, CVE


class Command(BaseCommand):
    help = "Sync Tactical RMM inventory and match it against CVEs."

    def handle(self, *args, **opts):
        self.stdout.write(self.style.WARNING("1. Pulling TRMM inventory..."))
        try:
            self.stdout.write("   " + sync_trmm())
        except TRMMError as e:
            self.stderr.write(self.style.ERROR(str(e)))
            return

        if CVE.objects.count() == 0:
            self.stdout.write(self.style.WARNING(
                "   No CVEs in the store yet — run `run_watch_loop --live` first, "
                "or wait for the nightly pull, then re-run this."))

        self.stdout.write(self.style.WARNING("2. Matching inventory against CVEs..."))
        self.stdout.write("   " + watch_loop())

        watch = Finding.objects.filter(source="watch").count()
        self.stdout.write(self.style.SUCCESS(f"\n{watch} watch findings on the dashboard."))
