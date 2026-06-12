"""
Load the entire local cvelistV5 mirror into the CVE store + token index so the
matcher works against every CVE, not just KEV-plus-recent.

    docker compose exec web python manage.py load_cve_corpus

Run once after the first mirror clone (it's a few hundred thousand records, so
give it several minutes). Cheap to re-run — it upserts.
"""
from django.core.management.base import BaseCommand
from core.tasks import load_cve_corpus
from core import feeds


class Command(BaseCommand):
    help = "Load the full cvelistV5 corpus into the CVE store and token index."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=0,
                            help="Stop after N records (for a quick test run).")

    def handle(self, *args, **opts):
        if not feeds.mirror_present():
            self.stdout.write(self.style.ERROR(
                f"No mirror at {feeds.CVELIST_DIR}. Run update_cve_mirror first."))
            return
        self.stdout.write(self.style.WARNING(
            "Loading the full CVE corpus — this can take several minutes..."))
        result = load_cve_corpus(limit=opts["limit"])
        self.stdout.write(self.style.SUCCESS(result))
