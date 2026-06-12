"""
Ad-hoc external assessment of a single domain or IP — no tenant setup required.
Point it at a target and go; results land under a holding "Ad-hoc" tenant (or a
tenant you name with --tenant) and show up in the dashboard, reassignable later.

    docker compose exec scan-worker python manage.py assess radiocheck.me
    docker compose exec scan-worker python manage.py assess 94.175.206.226 --authorised
    docker compose exec scan-worker python manage.py assess radiocheck.me --tenant acme --ports

Because this actively probes the target, it asks you to confirm authorisation
(§11) unless you pass --authorised. Passive subfinder aside, httpx/naabu touch
the host — so the confirmation covers you. IP targets skip subfinder.
"""
from django.core.management.base import BaseCommand, CommandError
from core.models import Tenant, Asset
from core.tasks import external_discovery
from core import discovery

HOLDING_SLUG = "ad-hoc"


class Command(BaseCommand):
    help = "Discover and fingerprint a single domain or IP, ad-hoc."

    def add_arguments(self, parser):
        parser.add_argument("target", help="Domain or IP to assess.")
        parser.add_argument("--tenant", default=None,
                            help="Attribute results to this tenant slug "
                                 "(default: a holding 'Ad-hoc' tenant).")
        parser.add_argument("--ports", action="store_true",
                            help="Also run a naabu port sweep.")
        parser.add_argument("--nuclei", action="store_true",
                            help="Also run a deep Nuclei scan of this target "
                                 "(finds CVEs/misconfigs httpx's fingerprint misses).")
        parser.add_argument("--authorised", action="store_true",
                            help="Skip the interactive authorisation prompt (§11).")

    def handle(self, *args, **opts):
        target = opts["target"].strip()

        # Resolve the tenant: a named one, or the shared holding bucket.
        if opts["tenant"]:
            try:
                tenant = Tenant.objects.get(slug=opts["tenant"])
            except Tenant.DoesNotExist:
                raise CommandError(f"No tenant with slug '{opts['tenant']}'.")
        else:
            tenant, _ = Tenant.objects.get_or_create(
                slug=HOLDING_SLUG,
                defaults={"name": "Ad-hoc / Unassigned", "scanning_authorised": True})

        # §11 consent. The per-run confirmation is the real gate here, not a
        # standing tenant flag.
        if not opts["authorised"]:
            self.stdout.write(self.style.WARNING(
                f"\nAbout to ACTIVELY probe '{target}'. Only proceed if you are "
                f"authorised to assess this target (§11)."))
            ans = input("Type 'yes' to confirm: ").strip().lower()
            if ans not in ("y", "yes"):
                self.stdout.write(self.style.ERROR("Aborted — no confirmation."))
                return

        # Make sure the holding tenant can run (the run is already consented).
        if not tenant.scanning_authorised:
            self.stdout.write(self.style.ERROR(
                f"Tenant '{tenant.slug}' is not scanning_authorised — "
                f"either authorise it in admin or drop --tenant."))
            return

        # Seed the target as an asset so it's tracked even if nothing's live.
        kind = Asset.Kind.IP if discovery.looks_like_ip(target) else Asset.Kind.DOMAIN
        Asset.objects.get_or_create(
            tenant=tenant, target=target,
            defaults={"name": target, "kind": kind, "internet_facing": True})

        self.stdout.write(self.style.WARNING(
            f"Assessing {target} (under tenant '{tenant.slug}'): "
            f"{'httpx' if kind == Asset.Kind.IP else 'subfinder -> httpx'}"
            f"{' -> naabu' if opts['ports'] else ''}..."))

        result = external_discovery(tenant.id, roots=[target], do_ports=opts["ports"])
        style = self.style.ERROR if ("ABORTED" in result or "not found" in result) else self.style.SUCCESS
        self.stdout.write(style(result))

        # Optional deep pass: Nuclei against just this target's hosts.
        if opts["nuclei"]:
            from core.tasks import nuclei_scan
            from core.models import Finding
            scan_targets = [a.target for a in
                            tenant.assets.filter(target__icontains=target.split("/")[0])
                            if a.target] or [target]
            self.stdout.write("Running Nuclei (deep pass — this can take a while)...")
            self.stdout.write(self.style.SUCCESS(
                nuclei_scan(tenant.id, only_targets=scan_targets)))
            hits = Finding.objects.filter(
                tenant=tenant, source="nuclei",
                asset__target__icontains=target.split("/")[0]).select_related("asset")
            if hits:
                self.stdout.write("\nNuclei findings:")
                for f in hits.order_by("priority"):
                    self.stdout.write(
                        f"  {f.priority}  [{f.severity:<8}] {f.title}  ({f.matched_at})")

        # Show the surface for just this run's hosts.
        live = tenant.assets.filter(internet_facing=True).order_by("target")
        if live:
            self.stdout.write("\nExternal surface:")
            for a in live:
                prods = ", ".join(
                    f"{p.name} {p.version}".strip() for p in a.products.all()[:8]) or "—"
                self.stdout.write(f"  {a.target:<40} {a.get_kind_display():<12} {prods}")
        self.stdout.write(self.style.HTTP_INFO(
            "\nResults are in the dashboard. Run run_watch_loop to match products against the CVE store."))
