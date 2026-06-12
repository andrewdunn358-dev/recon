"""
Run external attack-surface discovery for a tenant: enumerate subdomains, probe
which are live, fingerprint the stack, and ingest as Assets + Products. Run in
the scan-worker container (it carries subfinder/httpx/naabu):

    docker compose exec scan-worker python manage.py discover_tenant <slug>
    docker compose exec scan-worker python manage.py discover_tenant <slug> \
        --root example.org --root example.com --ports

Roots default to the tenant's domain assets. Gated on scanning_authorised (§11).
"""
from django.core.management.base import BaseCommand, CommandError
from core.models import Tenant, Asset, Product
from core.tasks import external_discovery


class Command(BaseCommand):
    help = "Enumerate and fingerprint a tenant's external surface."

    def add_arguments(self, parser):
        parser.add_argument("slug", help="Tenant slug.")
        parser.add_argument("--root", action="append", default=[],
                            help="Root domain to enumerate (repeatable). "
                                 "Defaults to the tenant's domain assets.")
        parser.add_argument("--ports", action="store_true",
                            help="Also run a naabu port sweep (slower).")

    def handle(self, *args, **opts):
        try:
            tenant = Tenant.objects.get(slug=opts["slug"])
        except Tenant.DoesNotExist:
            raise CommandError(f"No tenant with slug '{opts['slug']}'.")

        if not tenant.scanning_authorised:
            self.stdout.write(self.style.ERROR(
                "Tenant is not authorised for scanning (§11). Tick 'scanning "
                "authorised' in admin once you have written sign-off."))
            return

        roots = opts["root"] or [a.target for a in
                                 tenant.assets.filter(kind=Asset.Kind.DOMAIN) if a.target]
        self.stdout.write(self.style.WARNING(
            f"Discovering {tenant.name}: roots = {', '.join(roots) or '(none — add a domain asset)'}"))
        self.stdout.write("Running subfinder -> httpx" +
                          (" -> naabu" if opts["ports"] else "") + " (this can take a while)...")

        result = external_discovery(tenant.id, roots=opts["root"] or None,
                                    do_ports=opts["ports"])
        style = self.style.ERROR if "ABORTED" in result or "not found" in result else self.style.SUCCESS
        self.stdout.write(style(result))

        # Show what landed.
        assets = tenant.assets.filter(internet_facing=True).order_by("target")
        if assets:
            self.stdout.write("\nExternal surface:")
            for a in assets:
                prods = ", ".join(
                    f"{p.name} {p.version}".strip() for p in a.products.all()[:6]) or "—"
                self.stdout.write(f"  {a.target:<40} {a.get_kind_display():<12} {prods}")
        self.stdout.write(self.style.HTTP_INFO(
            "\nNext: run the watch loop to match these products against the CVE store."))
