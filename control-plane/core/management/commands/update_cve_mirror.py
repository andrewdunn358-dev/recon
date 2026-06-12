"""
Clone or refresh the local cvelistV5 mirror. First run clones (a few GB onto the
persistent volume); after that it pulls only the daily deltas.

    docker compose exec web python manage.py update_cve_mirror

Once the mirror exists, run_watch_loop --live reads CVE records from local disk
instead of GitHub — fast, no rate limits.
"""
from django.core.management.base import BaseCommand
from core.tasks import update_cve_mirror
from core import feeds


class Command(BaseCommand):
    help = "Clone/refresh the local cvelistV5 mirror used by the feed pull."

    def handle(self, *args, **opts):
        present = feeds.mirror_present()
        self.stdout.write(self.style.WARNING(
            f"{'Updating' if present else 'Cloning'} cvelistV5 mirror at {feeds.CVELIST_DIR} "
            f"{'(deltas only)' if present else '(first run — a few GB, give it a few minutes)'}..."))
        result = update_cve_mirror()
        style = self.style.SUCCESS if "ok" in result else self.style.ERROR
        self.stdout.write(style(result))
