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

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset", action="store_true",
            help="Clear existing tenants/assets/findings first, then rebuild "
                 "cleanly. Use once to clear duplicates from earlier runs.")
        parser.add_argument(
            "--wait", action="store_true",
            help="Run CVE matching inline and wait for it (default: hand matching "
                 "to the worker and return as soon as inventory is in).")

    def handle(self, *args, **opts):
        if not SYNTHOPS_URL:
            raise CommandError("SYNTHOPS_URL is not set — add it (and SYNTHOPS_USER/"
                               "SYNTHOPS_PASSWORD) to the environment.")
        if opts["reset"]:
            self.stdout.write(self.style.WARNING(
                "RESET: clearing all tenants/assets/findings, then rebuilding."))
        self.stdout.write(self.style.WARNING(f"Syncing from {SYNTHOPS_URL}…"))
        try:
            result = sync_synthops(reset=opts["reset"],
                                   match="inline" if opts["wait"] else "async")
        except SynthOpsError as e:
            raise CommandError(str(e))
        self.stdout.write(self.style.SUCCESS(result))
