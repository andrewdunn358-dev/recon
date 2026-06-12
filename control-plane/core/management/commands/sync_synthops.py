"""
Sync Recon's inventory from SynthOps: clients -> tenants, servers/workstations ->
assets, per-agent software -> products, then match against the CVE store.

    docker compose exec web python manage.py sync_synthops

Needs SYNTHOPS_URL / SYNTHOPS_USER / SYNTHOPS_PASSWORD in the environment.
This supersedes sync_trmm — SynthOps already aggregates TRMM.
"""
from django.core.management.base import BaseCommand, CommandError
from core.tasks import sync_synthops
from core.integrations.synthops import SynthOpsError, SYNTHOPS_URL


class Command(BaseCommand):
    help = "Pull clients/assets/software from SynthOps and match against CVEs."

    def handle(self, *args, **opts):
        if not SYNTHOPS_URL:
            raise CommandError("SYNTHOPS_URL is not set — add it (and SYNTHOPS_USER/"
                               "SYNTHOPS_PASSWORD) to the environment.")
        self.stdout.write(self.style.WARNING(f"Syncing from {SYNTHOPS_URL}…"))
        try:
            result = sync_synthops()
        except SynthOpsError as e:
            raise CommandError(str(e))
        self.stdout.write(self.style.SUCCESS(result))
