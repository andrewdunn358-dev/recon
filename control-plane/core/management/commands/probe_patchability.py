from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = ("Probe the estate's package managers (winget/choco) to record each "
            "product's fix path. Prints progress and total time.")

    def add_arguments(self, parser):
        parser.add_argument("--all", action="store_true",
                            help="Include offline devices (default: online only).")
        parser.add_argument("--no-force", action="store_true",
                            help="Respect the recent-probe guard (default: force a fresh run).")

    def handle(self, *args, **opts):
        from core.tasks import probe_patchability
        result = probe_patchability(
            only_online=not opts["all"],
            force=not opts["no_force"],
        )
        self.stdout.write(self.style.SUCCESS(f"probe result: {result}"))
