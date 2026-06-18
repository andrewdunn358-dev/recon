from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = ("List saved TRMM scripts with their ids, so you can find the pk for "
            "TRMM_REMEDIATE_SCRIPT_ID / TRMM_PROBE_SCRIPT_ID. Pass a word to filter.")

    def add_arguments(self, parser):
        parser.add_argument("filter", nargs="?", default="",
                            help="Optional case-insensitive name filter, e.g. 'recon'.")

    def handle(self, *args, **opts):
        from core.integrations import trmm
        try:
            scripts = trmm.list_scripts()
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Could not reach TRMM: {e}"))
            return
        needle = (opts["filter"] or "").lower()
        rows = [s for s in scripts if needle in (s["name"] or "").lower()]
        rows.sort(key=lambda s: (s["name"] or "").lower())
        if not rows:
            self.stdout.write("No scripts matched.")
            return
        for s in rows:
            self.stdout.write(f"{str(s['id']).rjust(5)}  {s['name']}")
